"""Compact evidence-first reporting; exhaustive source records remain in CSV/JSON."""
from __future__ import annotations
from collections import Counter
import csv
import json
from .exporting import export_stream,safe_csv_cell


def refs_text(item,limit=None):
    refs=item.get('references',[]);chosen=refs if limit is None else refs[:limit]
    text='\n'.join(f"{r['plugin']} / {r['run_id']} / row {r['row_id']}" for r in chosen)
    if limit is not None and len(refs)>limit:text+=f'\n{len(refs)-limit} additional references in findings.json / findings.csv.'
    return text


def primary_findings(model):
    return [f for f in model.get('findings',[]) if f.get('layer')!='Context']


def endpoint(row):
    def value(addr,port):return ('['+addr+']' if ':' in addr else addr)+(':'+port if port else '')
    return value(row['local_address'],row['local_port'])+' -> '+value(row['remote_address'],row['remote_port'])


def network_preview(model,limit):
    # RDP/SSH etc. context must not be buried behind arbitrary row ordering.
    rows=model.get('network_context',[])
    return sorted(rows,key=lambda r:(not bool(r.get('port_context')),r.get('time_utc') or '9999',r['run_id'],r['row_id']))[:limit]


def html_table(out,headers,rows,esc):
    out.write('<div class="table-scroll"><table><tr>'+''.join('<th>'+esc(x)+'</th>' for x in headers)+'</tr>')
    for row in rows:out.write('<tr>'+''.join('<td>'+esc(x).replace('\n','<br/>')+'</td>' for x in row)+'</tr>')
    out.write('</table></div>')


def html_details(out,model,esc,chart):
    out.write('<section class="section" id="findings"><h2>Evidence-led assessment</h2>')
    out.write('<p>'+esc(model.get('finding_limits',''))+'</p>')
    assessment=model['case'].get('analyst_assessment')
    if assessment:
        if model.get('analyst_assessment_stale'):out.write('<p class="notice">STALE ASSESSMENT: evidence changed after the analyst conclusion; re-review required.</p>')
        out.write('<h3>Analyst-entered conclusion (not an automated verdict)</h3><pre>'+esc(json.dumps(assessment,indent=2,ensure_ascii=False))+'</pre>')
    else:out.write('<p class="notice">No analyst-entered final disposition. Automated rules identify leads; neither completed jobs nor zero findings establish a clean system.</p>')
    out.write('<h3>Investigation scope</h3><p>'+esc(model.get('investigation','Custom'))+'</p>')
    goal=model.get('investigation_goal',{})
    out.write('<p>'+esc(goal.get('question',''))+'</p><p>'+esc(goal.get('limit',''))+'</p>')
    gaps=model.get('planning_gaps',[])
    if gaps:
        out.write('<h3>Preflight: selected but not run</h3>')
        html_table(out,['Task','State','Reason'],[[g['plugin'],g['status'],g['reason']] for g in gaps],esc)
    out.write(chart('Actionable review items by category (not confirmed infections)',model.get('finding_categories',{}).items()))
    out.write(chart('Review priorities (not malware severity)',model.get('finding_priorities',{}).items()))
    findings=primary_findings(model)
    out.write('<h2>Specific findings and data-quality limitations</h2>')
    if not findings:out.write('<p>No actionable rule or quality warning was produced for the reviewed scope. This is not a clean-system conclusion.</p>')
    for f in findings:
        out.write('<article class="note"><h3>'+esc(f['id']+' / '+f['title'])+'</h3><p class="tag">'+esc(f['priority']+' / '+f['status'])+'</p>')
        for label,key in [('Observation','observation'),('Context','context'),('Assessment','interpretation'),('Next action','action')]:
            out.write('<p><strong>'+label+'</strong></p><pre>'+esc(f.get(key,''))+'</pre>')
        out.write('<small>'+esc(f['confidence'])+'</small><details><summary>Source references</summary><pre>'+esc(refs_text(f))+'</pre></details></article>')
    contexts=[f for f in model.get('findings',[]) if f.get('layer')=='Context']
    if contexts:
        out.write('<h3>Context, not an actionable malware finding</h3>')
        html_table(out,['Item','Observation','Meaning'],[[f['title'],f['observation'],f['interpretation']] for f in contexts],esc)
    out.write('<h3>Noise reduction / preserved context</h3><p>Original engine output is unchanged. These matches were withheld from actionable findings; suppression-ledger.csv preserves source references and reasons.</p>')
    html_table(out,['Reason','Source rows'],list(model.get('suppression_counts',{}).items()),esc)
    out.write(f'<p>{len(model.get("script_references",[]))} actual interpreter/configuration/file references are retained in script-references.csv. A normal interpreter or file reference alone is not a malicious finding.</p></section>')
    html_network(out,model,esc,chart)
    out.write('<section class="section"><h2>Authentication and session chronology</h2><p>Events below are imported evidence. They are not inferred from open ports or process creation. Hosts, providers, channels and input-file provenance remain separate. No session-duration or authorization inference is automatic.</p>')
    events=model.get('event_timeline',[])
    if not events:out.write('<p class="notice">No relevant supplemental event records were imported. The time when an RDP user authenticated cannot be established from this report alone.</p>')
    else:
        html_table(out,['UTC / PHT (UTC+08:00)','Host / event / record','Observed activity','Account / source','Interpretation'],
            [[event_time(e),event_source(e),e['kind'],e.get('account','')+' / '+e.get('source_address',''),e['interpretation']] for e in events[:200]],esc)
        out.write(f'<p>Showing {min(200,len(events))} of {len(events)} event records; all records and provenance in event-timeline.csv.</p>')
    if model.get('event_sources'):
        html_table(out,['Input','SHA-256','Coverage / origin'],[[s['original_path'],s['sha256'],s['coverage']+' / '+s['origin']] for s in model['event_sources']],esc)
    for issue in model.get('event_issues',[]):out.write('<p class="notice">'+esc(issue)+'</p>')
    out.write('<h3>Memory-object chronology</h3><p>Process creation/exit and network-object creation are not interchangeable with logon events. UTC and PHT are conversions of the source time, not new evidence.</p>')
    timeline=model.get('memory_timeline',[])
    html_table(out,['UTC / PHT','Type / field','Subject','Source'],[[event_time(e),e['kind']+' / '+e['timestamp_field'],e['subject'],refs_text(e,2)] for e in timeline[:50]],esc)
    out.write(f'<p>Showing {min(50,len(timeline))} of {len(timeline)} memory-timeline rows. All in memory-timeline.csv.</p></section>')
    out.write('<section class="section"><h2>Computed binary hashes</h2><p>Hashes below identify actual copied or extracted bytes. A process ID has no fixed hash. Reconstructed memory PE images can differ from original on-disk files. Signature validity is not checked; not verified does not mean unsigned.</p>')
    binaries=model.get('binary_evidence',[])
    if not binaries:out.write('<p>No executable bytes have been collected; executable hashes are unavailable. Use Evidence lab to collect selected PE images or add a preserved acquired file.</p>')
    html_table(out,['Artifact / PID','SHA-256 / representation','Integrity / structure','Intelligence'],[[b['case_path']+' / PID '+str(b.get('pid')),b.get('sha256') or 'Unavailable',b['representation']+'\n'+b['integrity']+'\n'+b['structure'],b['reputation']] for b in binaries],esc)
    for issue in model.get('binary_issues',[]):out.write('<p class="notice">'+esc(issue)+'</p>')
    out.write('</section><section class="section"><h2>Memory regions and data quality</h2>')
    if model.get('malfind_groups'):out.write(chart('Candidate memory regions (not infections)',model['malfind_groups']))
    out.write(chart('Process plausibility checks',[('Objects passing basic checks',model.get('plausible_process_objects',0)),('pslist rows requiring validation',model.get('excluded_pslist_rows',0))]))
    out.write('<p>Passing checks is not authentication of a process. Runtime-generated code and instrumentation can resemble injection. Full context is in quality-flags.csv, process-inventory.csv and malfind-regions.csv.</p>')
    out.write(f'<p>{len(model.get("excluded_observables",[]))} path/version matches kept out of the observable list. Original values remain in observable-exclusions.csv.</p></section>')


def event_time(e):
    return (e.get('time_utc') or e.get('time_status','Unavailable'))+'\n'+(e.get('time_pht') or 'PHT unavailable')


def event_source(e):
    return e.get('host','Unknown host')+'\n'+str(e.get('event_id',''))+' / record '+str(e.get('record_id',''))


def pdf_details(model,p,table,chart,page_break,space,width):
    from reportlab.platypus import CondPageBreak
    story=[p('Investigation scope','h2'),p(model.get('investigation','Custom'),'h3')]
    goal=model.get('investigation_goal',{})
    story += [p(goal.get('question','')),p(goal.get('limit',''),'small')]
    assessment=model['case'].get('analyst_assessment')
    if assessment:
        if model.get('analyst_assessment_stale'):story.append(p('STALE ASSESSMENT: evidence changed after the recorded conclusion. Re-review required.'))
        story += [p('Analyst-entered conclusion','h3'),p(assessment.get('disposition','')),p(assessment.get('reason','')),p('Supporting references: '+assessment.get('references',''),'small'),p('Recorded by '+assessment.get('analyst','')+' / '+assessment.get('utc',''),'small')]
    else:story += [p('No analyst-entered final disposition. Automated rules do not establish a clean system or confirmed compromise.','small')]
    gaps=model.get('planning_gaps',[])
    if gaps:
        story += [p('Preflight: selected but not run','h3'),table([['PLUGIN / TASK','REASON']]+[[g['plugin'],g['reason']] for g in gaps],[width*.42,width*.58],True)]
    findings=primary_findings(model)
    story += [p('Actionable findings and quality limitations','h2'),p(model.get('finding_limits',''),'small')]
    if model.get('finding_categories'):story.append(chart(model['finding_categories'].items()))
    if not findings:story.append(p('No actionable rule or quality warning was generated. Unexamined areas and unavailable evidence remain unknown.'))
    else:
        story.append(table([['ID / PRIORITY','REVIEW ITEM','STATUS']]+[[f['id']+' / '+f['priority'],f['title'],f['status']] for f in findings[:30]],[80,width-200,120],True))
    if len(findings)>30:story.append(p(f'PDF detail is limited to 30 of {len(findings)} items. Full findings and references remain in HTML/CSV/JSON.','small'))
    for f in findings[:30]:
        story += [CondPageBreak(135),p(f['id']+' / '+f['title'],'h3'),p(f['priority']+' / '+f['confidence'],'small')]
        for title,key in [('Observation','observation'),('Context','context'),('Assessment','interpretation'),('Next action','action')]:
            text=str(f.get(key,''));clipped=text[:1000]+(' [Full text in HTML/JSON]' if len(text)>1000 else '')
            paragraph=p(title+': '+clipped)
            if key=='action':paragraph.keepWithNext=True
            story.append(paragraph)
        story += [p(refs_text(f,3),'small'),space(1,6)]
    contexts=[f for f in model.get('findings',[]) if f.get('layer')=='Context']
    if contexts:
        story += [p('Context / not a malware finding','h2'),table([['CONTEXT','OBSERVATION']]+[[f['title'],f['observation'][:450]] for f in contexts[:12]],[width*.38,width*.62],True),p(f'{len(contexts)} context groups. Remote tooling or a conventional port does not establish unauthorized access. Full context in findings.csv.','small')]
    story += [p('Noise reduction / retained evidence','h2'),p('Background matches are withheld from actionable findings, not deleted. Every source row remains available.','small')]
    counts=model.get('suppression_counts',{})
    if counts:story.append(table([['REASON','SOURCE ROWS']]+[[k,str(v)] for k,v in counts.items()],[width-70,70],True))
    else:story.append(p('No known background/configuration matches required suppression in the reviewed output.','small'))
    story.append(p(f'{len(model.get("script_references",[]))} interpreter/configuration/file references retained as context. script-references.csv and suppression-ledger.csv retain provenance.','small'))
    story += pdf_network(model,p,table,chart,space,width)
    story += [CondPageBreak(180),p('Authentication and session timeline','h2'),p('Imported event evidence only. Network creation time is not authentication time. Hosts are kept separate; no authorization or automatic session-duration conclusion.','small')]
    events=model.get('event_timeline',[])
    if not events:story.append(p('No relevant supplemental event records imported. RDP authentication/session times are not established by this report alone.'))
    else:
        data=[['UTC / PHT (UTC+08:00)','HOST / EVENT / RECORD','OBSERVED ACTIVITY / ACCOUNT']]
        for e in events[:25]:data.append([event_time(e),event_source(e),e['kind']+'\n'+e.get('account','')+' / '+e.get('source_address','')])
        story += [table(data,[width*.32,width*.24,width*.44],True),p(f'Showing {min(25,len(events))} of {len(events)} imported records. Provider/channel, original values, provenance and limits are in event-timeline.csv.','small')]
    for source in model.get('event_sources',[])[:10]:
        story += [p(source['original_path']+'\nSHA-256 '+source['sha256']+'\n'+source['origin']+' / '+source['coverage'],'small')]
    story += [p('Memory-object chronology','h3'),p('Process lifecycle and network-object creation only; these are not user-logon times. Full chronology: memory-timeline.csv.','small')]
    timeline=model.get('memory_timeline',[])
    if timeline:
        story.append(table([['UTC / PHT','TIMESTAMP TYPE','SUBJECT']]+[[event_time(e),e['kind'],str(e.get('pid',''))+' / '+e['subject']] for e in timeline[:10]],[width*.32,width*.25,width*.43],True))
        story.append(p(f'Showing {min(10,len(timeline))} of {len(timeline)} memory timeline rows. Source fields and references are retained in CSV.','small'))
    story += [CondPageBreak(170),p('Executable bytes and SHA-256','h2'),p('A process ID is not a hashable executable. Hashes describe exact collected bytes. Reconstructed memory images are not necessarily original on-disk files. Signatures: not verified.','small')]
    binaries=model.get('binary_evidence',[])
    if not binaries:story.append(p('No binary bytes collected. Executable hashes unavailable; use Evidence lab to collect a selected PE or add a preserved acquired file.'))
    for b in binaries[:20]:
        story += [CondPageBreak(100),p(b['case_path']+' / PID '+str(b.get('pid','-')),'h3'),p('SHA-256: '+(b.get('sha256') or 'Unavailable'),'small'),p(b['representation']+' / '+b['integrity']+'\n'+b['structure']+'\n'+b['reputation'],'small')]
    if len(binaries)>20:story.append(p(f'Showing 20 of {len(binaries)} binary artifacts. Full inventory: executable-hashes.csv.','small'))
    for issue in model.get('binary_issues',[])+model.get('event_issues',[]):story.append(p('Evidence warning: '+issue))
    if model.get('malfind_groups'):
        story += [p('Candidate executable regions','h2'),chart(model['malfind_groups']),p('Regions, not infections. Mapped jump targets and individual source records are retained in malfind-regions.csv.','small')]
    story += [p('Process-data quality','h2'),chart([('Objects passing basic checks',model.get('plausible_process_objects',0)),('pslist rows requiring validation',model.get('excluded_pslist_rows',0))]),p('Plausibility is not legitimacy. Raw rows remain unchanged; quality flags are exported separately.','small')]
    return story


def html_network(out,model,esc,chart):
    rows=model.get('network_context',[])
    out.write('<section class="section"><h2>Network evidence and creation timestamps</h2>')
    if not rows:out.write('<p>No indexed network records. This does not exclude past or unobserved communication.</p></section>');return
    out.write(chart('Recovered network rows by state (not unique sessions)',Counter(str(r.get('state') or 'Not reported') for r in rows).items()))
    html_table(out,['PID / owner','Endpoints','State / context','Created UTC / PHT','Time meaning / source'],
        [[str(r['pid'])+' / '+r['owner'],endpoint(r),r['state']+' / '+r['port_context'],event_time(r),r['timestamp_kind']+'\n'+r['timestamp_field']+'\n'+r['plugin']+' / row '+str(r['row_id'])] for r in network_preview(model,50)],esc)
    out.write(f'<p>Showing {min(50,len(rows))} of {len(rows)} source rows; all in network-context.csv. Unavailable times are not filled with capture or report-generation time.</p></section>')


def pdf_network(model,p,table,chart,space,width):
    from reportlab.platypus import CondPageBreak
    rows=model.get('network_context',[])
    if not rows:return []
    story=[CondPageBreak(200),p('Network evidence / object creation times','h2'),p('Network-object creation is not RDP authentication, desktop logon or session duration. Unknown source times stay unavailable.','small'),chart(Counter(str(r.get('state') or 'Not reported') for r in rows).items())]
    data=[['PID / OWNER','LOCAL -> REMOTE','STATE / CONTEXT','CREATED UTC / PHT']]
    for r in network_preview(model,12):data.append([str(r['pid'] or '-')+' / '+(r['owner'] or '-'),endpoint(r),r['state']+' / '+r['port_context'],event_time(r)])
    story += [table(data,[width*.16,width*.31,width*.23,width*.30],True),p(f'Showing {min(12,len(rows))} of {len(rows)} source rows. Cross-plugin records may overlap. Full original rows and timestamp fields: network-context.csv.','small'),space(1,8)]
    return story


def write_detail_csv(case,destination,items,fields):
    with export_stream(case,destination) as out:
        writer=csv.writer(out,lineterminator='\n');writer.writerow(fields)
        for item in items:
            values=[]
            for field in fields:
                value=item.get(field,'')
                if isinstance(value,(dict,list,tuple)):value=json.dumps(value,ensure_ascii=False)
                values.append(safe_csv_cell(value))
            writer.writerow(values)


def export_detail_files(case,folder,model):
    paths={}
    tables=[
      ('network','network-context.csv','network_context',['plugin','run_id','row_id','pid','owner','local_address','local_port','remote_address','remote_port','state','protocol','port_context','timestamp_field','timestamp_kind','time_raw','time_utc','time_pht','time_status','interpretation','record']),
      ('remote','remote-access.csv','remote_access_records',['tool','pid','reference','record']),
      ('scripts','script-references.csv','script_references',['plugin','run_id','row_id','pid','kind','interpreter','command','meaning','record']),
      ('search','search-matches.csv','keyword_matches',['plugin','run_id','row_id','pid','term','record']),
      ('planning','planning-not-run.csv','planning_gaps',['plugin','status','reason','job']),
      ('findings','findings.csv','findings',['id','layer','priority','category','title','pid','process','status','confidence','observation','context','interpretation','action','references']),
      ('quality','quality-flags.csv','quality_flags',['plugin','run_id','row_id','pid','process','reasons','record']),
      ('regions','malfind-regions.csv','malfind_regions',['plugin','run_id','row_id','pid','process','start','end','protection','jump_target','target_module','target_reference','context','record']),
      ('exclusions','observable-exclusions.csv','excluded_observables',['plugin','run_id','row_id','field','value','reason','context']),
      ('suppression','suppression-ledger.csv','suppressed_records',['plugin','run_id','row_id','pid','reason','record']),
      ('processes','process-inventory.csv','process_inventory',['pid','process','ppid','paths','command','created','exited','object_identities','identity_status','parent_context','hash_status','hashes','references']),
      ('binaries','executable-hashes.csv','binary_evidence',['id','pid','process','captured_path','case_path','sha256','size','representation','hash_scope','association','format','structure','integrity','signature_status','reputation','intelligence_matches','reference']),
      ('events','event-timeline.csv','event_timeline',['time_raw','time_utc','time_pht','time_status','kind','timestamp_field','host','provider','channel','event_id','record_id','account','domain','source_address','session_id','logon_id','logon_type','origin','interpretation','data','reference','import_references']),
      ('memory_timeline','memory-timeline.csv','memory_timeline',['time_raw','time_utc','time_pht','time_status','kind','timestamp_field','pid','subject','identity','interpretation','references'])]
    for key,name,field,columns in tables:
        path=folder/name;write_detail_csv(case,path,model.get(field,[]),columns);paths[key]=path
    for key,name,data in [('finding_json','findings.json',model.get('findings',[])),('plan_json','investigation-plan.json',model.get('preflight',{})),('event_sources','event-sources.json',model.get('event_sources',[]))]:
        path=folder/name
        with export_stream(case,path) as stream:json.dump(data,stream,ensure_ascii=False,indent=2)
        paths[key]=path
    return paths
