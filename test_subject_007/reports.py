"""Self-contained HTML, vector PDF and ordinary CSV report exports.

No browser, network, JavaScript, LaTeX or external chart service is required.
All charts derive from indexed records and label the counting basis.
"""
from __future__ import annotations
from contextlib import closing, contextmanager
import csv
import html
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import uuid
from .exporting import export_stream, safe_destination, safe_csv_cell
from .results import iter_rows, query_rows
from .summary import build_summary
from .util import Cancelled, atomic_json, hash_file, slug, utc_now
from .paths import user_path
from .report_details import html_details, pdf_details, export_detail_files

BG, CARD, LINE, TEXT, MUTED, RED = '#101012', '#19191c', '#343438', '#eeeef0', '#a0a0a8', '#d95b65'


def clean(value) -> str:
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value))


def esc(value) -> str:
    return html.escape(clean(value), quote=True)


def short_plugin(name):
    parts = name.split('.')
    return '.'.join(parts[:-1]) if len(parts) > 1 else name


def chart_svg(title, items, max_items=12):
    items = list(items)[:max_items]
    if not items:
        return '<p class="muted">No data available for this chart.</p>'
    width, left, bar, row = 880, 295, 500, 33
    height = 28 + len(items) * row
    maximum = max([n for _, n in items] + [1])
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{esc(title)}" viewBox="0 0 {width} {height}">',
           f'<title>{esc(title)}</title>']
    for i, (label, number) in enumerate(items):
        y = 12 + i * row
        out.append(f'<text x="0" y="{y+15}" fill="{MUTED}" font-family="monospace" font-size="12">{esc(label[:39])}</text>')
        out.append(f'<rect x="{left}" y="{y}" width="{bar}" height="20" fill="{LINE}"/>')
        out.append(f'<rect x="{left}" y="{y}" width="{bar*number/maximum:.2f}" height="20" fill="{TEXT}"/>')
        out.append(f'<text x="{left+bar+16}" y="{y+15}" fill="{TEXT}" font-family="monospace" font-size="12">{number:,}</text>')
    return ''.join(out) + '</svg>'


def evidence_items(model):
    meta = model['case']
    return [('Case ID', meta['id']), ('Analyst', meta['analyst']),
            ('Captured OS (analyst selection)', meta['evidence_os']), ('Evidence path', meta['image']),
            ('Image size (bytes)', f"{meta['fingerprint']['size']:,}"), ('Import SHA-256', meta['sha256']),
            ('Last full verification (UTC)', meta.get('last_verified_utc', 'Not recorded')),
            ('Verification state', meta.get('verification', 'Unknown')),
            ('Audit snapshot', ('Valid' if model['audit_ok'] else 'INVALID') + f" / {model['audit_count']} events"),
            ('Audit snapshot head', model['audit_head'])]


def write_html(case, destination, model):
    with export_stream(case, destination) as out:
        out.write('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>Test Subject 007 | Memory analysis</title><style>
:root{color-scheme:dark}nav{margin-top:16px}a{color:#eeeef0}*{box-sizing:border-box}body{background:#101012;color:#eeeef0;font:15px/1.65 system-ui,sans-serif;margin:0}main{max-width:1120px;margin:auto;padding:48px 32px}header{border-bottom:1px solid #343438;padding-bottom:28px}.eyebrow,.mono{font-family:monospace}.eyebrow{letter-spacing:.12em;font-size:12px;color:#a0a0a8}h1{font-size:34px;line-height:1.2;letter-spacing:-.025em;overflow-wrap:anywhere;margin:20px 0 12px}h2{font-size:20px;margin:0 0 18px}h3{font-size:16px;overflow-wrap:anywhere}p{margin:10px 0}.muted,small{color:#a0a0a8}.tag{display:inline-block;border:1px solid #343438;border-left:3px solid #d95b65;padding:8px 12px;margin:8px 0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}.metric{background:#19191c;border:1px solid #343438;padding:18px}.metric b{display:block;font:28px monospace;margin-top:8px}.section{border-top:1px solid #343438;margin-top:32px;padding-top:24px}.notice{padding:16px 20px;background:#19191c;border-left:2px solid #d95b65}.table-scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th{font-weight:500;color:#a0a0a8;text-align:left;background:#19191c}td,th{padding:10px;border-bottom:1px solid #343438;vertical-align:top;overflow-wrap:anywhere}td.mono{font-size:11px;word-break:break-word}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}svg{width:100%;height:auto;max-height:560px;display:block}details{padding:12px 0}summary{cursor:pointer}.note{background:#19191c;padding:16px;margin-top:10px}footer{margin-top:40px;border-top:1px solid #343438;padding-top:16px;font:11px monospace;color:#a0a0a8}@media(max-width:650px){main{padding:24px 16px}.grid{grid-template-columns:1fr}h1{font-size:26px}}@media print{:root{color-scheme:light}body{background:#fff;color:#111}main{padding:10mm;max-width:none}.metric,.note,.notice,th{background:#f4f4f4;color:#111}.muted,small,.eyebrow{color:#555}td,th,.section,header,footer{border-color:#bbb}h2,h3{break-after:avoid}tr,.metric{break-inside:avoid}svg text{fill:#222}svg rect:nth-of-type(2n){fill:#555}}
</style></head><body><main>''')
        out.write('<header><div class="eyebrow">TEST SUBJECT 007 / MEMORY FORENSICS</div>')
        out.write(f'<h1>{esc(model["case"]["name"])}</h1><p class="muted">Generated {esc(model["generated_utc"])} / UTC</p>')
        out.write(f'<span class="tag">{esc(model["assessment"])}</span></header>')
        if model['case'].get('synthetic_fixture'):
            out.write('<p class="notice"><strong>SYNTHETIC DEMONSTRATION</strong> - fabricated test records; not a real investigation or engine validation.</p>')
        out.write('<nav><a href="#findings">Findings</a> &nbsp; / &nbsp; <a href="#coverage">Coverage</a> &nbsp; / &nbsp; <a href="#evidence">Evidence</a> &nbsp; / &nbsp; <a href="#provenance">Provenance</a></nav>')
        out.write('<div class="grid">')
        for title, value in [('Latest plugins completed', f'{model["complete_latest"]} / {len(model["latest"])}'),
                             ('Actionable review items', str(model.get('actionable_count',0))),
                             ('Background context groups', str(model.get('context_count',0)))]:
            out.write(f'<div class="metric"><small>{esc(title)}</small><b>{esc(value)}</b></div>')
        out.write(f'</div><section><h2>Assessment summary</h2><p class="notice">{esc(model["summary"])}</p>')
        for item in model['observations']:
            out.write('<p>' + esc(item) + '</p>')
        out.write('</section>')
        html_details(out,model,esc,chart_svg)
        out.write('<section class="section"><h2 id="coverage">Analysis coverage</h2>')
        out.write('<p class="muted">Indexed records from the latest attempt per plugin/argument set. Counts overlap across plugins; they are not threat counts. Chart shows up to 12 plugins.</p>')
        out.write(chart_svg('Latest attempt: indexed records per plugin', [(short_plugin(r['plugin']), r['rows']) for r in model['latest']]))
        out.write('<h3>Execution status / all attempts</h3>')
        out.write(chart_svg('Execution status of every recorded attempt', model['status_counts'].items()))
        out.write('<div class="table-scroll"><table><tr><th>Plugin</th><th>Status</th><th>Rows</th><th>Started (UTC)</th><th>Run ID</th></tr>')
        for run in model['runs']:
            out.write('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in (run['plugin'], run['status'], run.get('rows',0),run.get('started_utc',''),run['id'])) + '</tr>')
        out.write('</table></div></section><section class="section"><h2 id="evidence">Evidence and integrity</h2><table>')
        for title, value in evidence_items(model):
            out.write(f'<tr><th style="width:25%">{esc(title)}</th><td class="mono">{esc(value)}</td></tr>')
        out.write('</table><p class="muted">Audit snapshot taken before this export. A hash chain is not a signature or immutable storage. Preserve evidence and custody records separately.</p></section>')
        out.write('<section class="section"><h2>Recovered observables</h2><p class="muted">Automatically extracted from indexed output. These are NOT confirmed malicious IOCs. No network lookups were made.</p>')
        out.write(chart_svg('Distinct unvalidated observables by category', model['observable_categories'].items()))
        out.write(f'<p>Showing {min(100,len(model["observable_preview"]))} of {model["observable_total"]:,} distinct values. The separate observables CSV contains all extracted values.</p>')
        out.write('<div class="table-scroll"><table><tr><th>Type</th><th>Value</th><th>Matched records</th><th>First source reference</th></tr>')
        for item in model['observable_preview'][:100]:
            out.write(f'<tr><td>{esc(item["kind"])}</td><td class="mono">{esc(item["value"])}</td><td>{item["occurrences"]}</td><td>{esc(item["plugin"])}<br>{esc(item["run_id"])} / row {item["row_id"]}</td></tr>')
        out.write('</table></div></section>')
        out.write('<section class="section"><h2>Diagnostics and limitations</h2>')
        for failure in model['failures']:
            out.write(f'<h3>{esc(failure["plugin"])}</h3><p class="notice">{esc(failure["title"])}</p>')
            for action in failure['actions']:
                out.write('<p>' + esc(action) + '</p>')
            out.write('<pre>' + esc('\n'.join(failure['messages'])) + '</pre>')
        out.write('<p>' + esc(model['limits']) + '</p></section>')
        out.write('<section class="section"><h2>Recommended next actions</h2>')
        for i, item in enumerate(model['recommendations'], 1):
            out.write(f'<p>{i}. {esc(item)}</p>')
        out.write('</section><section class="section"><h2>Analyst notes and bookmarks</h2>')
        if not model['notes']:
            out.write('<p class="muted">No analyst notes were recorded.</p>')
        for note in model['notes']:
            out.write(f'<div class="note"><small>{esc(note["utc"])} / {esc(note["analyst"])} / {esc(note.get("run_id",""))} / row {esc(note.get("row_id",""))}</small><pre>{esc(note["text"])}</pre></div>')
        out.write('</section>')
        out.write('<section class="section"><h2 id="provenance">Run provenance</h2><p class="muted">Detailed machine-readable metadata and original logs remain in each case run folder.</p>')
        for run in model['runs']:
            out.write(f'<details><summary>{esc(run["plugin"])} / {esc(run["id"])}</summary><pre>{esc(json.dumps(run,ensure_ascii=False,indent=2))}</pre></details>')
        out.write('</section><footer>TEST SUBJECT 007 / LOCAL EVIDENCE / ANALYST REVIEW REQUIRED</footer></main></body></html>')


@contextmanager
def binary_output(case, destination):
    destination = safe_destination(case, Path(destination))
    fd, temporary = tempfile.mkstemp(prefix='.export-', dir=destination.parent)
    os.close(fd)
    try:
        yield temporary
        with open(temporary, 'rb+') as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def pdf_fonts():
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    if 'TSBody' in pdfmetrics.getRegisteredFontNames():
        return 'TSBody', 'TSBold'
    candidates = [(Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'), Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf')),
                  (Path(os.environ.get('WINDIR','C:/Windows')) / 'Fonts/segoeui.ttf', Path(os.environ.get('WINDIR','C:/Windows')) / 'Fonts/segoeuib.ttf')]
    for regular, bold in candidates:
        if regular.is_file() and bold.is_file():
            try:
                pdfmetrics.registerFont(TTFont('TSBody', str(regular)))
                pdfmetrics.registerFont(TTFont('TSBold', str(bold)))
                return 'TSBody', 'TSBold'
            except Exception:
                continue
    return 'Helvetica', 'Helvetica-Bold'


def write_pdf(case, destination, model):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable, KeepTogether, CondPageBreak
    font, bold = pdf_fonts()
    styles = {
        'body': ParagraphStyle('body', fontName=font, fontSize=9, leading=14, textColor=colors.HexColor(TEXT), spaceAfter=8, wordWrap='CJK'),
        'small': ParagraphStyle('small', fontName=font, fontSize=7.5, leading=11, textColor=colors.HexColor(MUTED), spaceAfter=5, wordWrap='CJK'),
        'title': ParagraphStyle('title', fontName=bold, fontSize=25, leading=31, textColor=colors.HexColor(TEXT), spaceAfter=12, wordWrap='CJK'),
        'h2': ParagraphStyle('h2', fontName=bold, fontSize=14, leading=19, textColor=colors.HexColor(TEXT), spaceBefore=14, spaceAfter=8, keepWithNext=False),
        'h3': ParagraphStyle('h3', fontName=bold, fontSize=10, leading=15, textColor=colors.HexColor(TEXT), spaceBefore=10, spaceAfter=7, keepWithNext=False),
        'cell': ParagraphStyle('cell', fontName=font, fontSize=7.5, leading=11, textColor=colors.HexColor(TEXT), wordWrap='CJK'),
        'label': ParagraphStyle('label', fontName=font, fontSize=7.5, leading=11, textColor=colors.HexColor(MUTED), wordWrap='CJK'),
    }
    def p(text, style='body'):
        return Paragraph(esc(text).replace('\n','<br/>'), styles[style])
    width = A4[0]-88
    def table(data, widths, header=False):
        cells = [[p(v, 'label' if header and i==0 else 'cell') for v in row] for i,row in enumerate(data)]
        value = Table(cells, colWidths=widths, repeatRows=1 if header else 0, hAlign='LEFT')
        value.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),8),
                                   ('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),5),
                                   ('BOTTOMPADDING',(0,0),(-1,-1),5),
                                   ('LINEBELOW',(0,0),(-1,-1),.4,colors.HexColor(LINE)),
                                   ('BACKGROUND',(0,0),(-1,0),colors.HexColor(CARD))]))
        return value
    class BarChart(Flowable):
        def __init__(self, items):
            super().__init__(); self.items=list(items)[:12]; self.width=width; self.height=max(28,len(self.items)*25+8)
        def draw(self):
            c=self.canv; left=190; space=width-left-45; maximum=max([n for _,n in self.items]+[1])
            c.setFont(font,7)
            for i,(title,n) in enumerate(self.items):
                y=self.height-22-i*25
                title=title[:43]
                while c.stringWidth(title,font,7)>left-12:
                    title=title[:-2]+'~'
                c.setFillColor(colors.HexColor(MUTED)); c.drawString(0,y+4,title)
                c.setFillColor(colors.HexColor(LINE)); c.rect(left,y,space,16,stroke=0,fill=1)
                c.setFillColor(colors.HexColor(TEXT)); c.rect(left,y,space*n/maximum,16,stroke=0,fill=1)
                c.drawRightString(width,y+4,f'{n:,}')
    def page(canvas, doc):
        canvas.saveState(); canvas.setFillColor(colors.HexColor(BG)); canvas.rect(0,0,*A4,stroke=0,fill=1)
        canvas.setStrokeColor(colors.HexColor(LINE)); canvas.line(44,A4[1]-48,A4[0]-44,A4[1]-48)
        canvas.setFillColor(colors.HexColor(RED)); canvas.rect(44,A4[1]-38,3,9,stroke=0,fill=1)
        canvas.setFillColor(colors.HexColor(MUTED)); canvas.setFont(font,8)
        canvas.drawString(56,A4[1]-37,'TEST SUBJECT 007 / MEMORY FORENSICS')
        if model['case'].get('synthetic_fixture'):
            canvas.setFont(font,7); canvas.drawRightString(A4[0]-44,A4[1]-37,'SYNTHETIC DEMO')
        canvas.setFont(font,7); canvas.drawString(44,30,'LOCAL EVIDENCE / ANALYST REVIEW REQUIRED')
        canvas.drawRightString(A4[0]-44,30,f'{doc.page:02d}'); canvas.restoreState()
    story=[p(model['case']['name'],'title'),p('Generated '+model['generated_utc']+' / UTC','small'),
           p(model['assessment'],'h3')]
    if model['case'].get('synthetic_fixture'):
        story.append(p('SYNTHETIC DEMONSTRATION - fabricated test records; not a real investigation.','h3'))
    story += [p(model['summary']), Spacer(1,6),
              table([['ACTIONABLE ITEMS','CONTEXT GROUPS','EXECUTION COVERAGE'],
                     [str(model.get('actionable_count',0)),str(model.get('context_count',0)),f'{model["complete_latest"]} / {len(model["latest"])}']], [width/3]*3,True),
              p('Key observations','h2')]
    story += [p(s) for s in model['observations']]
    coverage = [p('Latest attempt / record coverage','h2'),
                p('Counts can overlap across plugins and are not threat counts. Up to 12 plugins shown.','small')]
    if model['latest']:
        coverage += [BarChart([(short_plugin(r['plugin']),r['rows']) for r in model['latest']])]
    else:
        coverage += [p('No analysis runs are available.','small')]
    story += pdf_details(model,p,table,BarChart,PageBreak,Spacer,width)
    story.append(KeepTogether(coverage))
    story += [CondPageBreak(330),p('Evidence and integrity','h2'),table(evidence_items(model),[155,width-155]),
              p('Audit snapshot taken before export. A hash chain is not a signature or immutable storage. Preserve independent custody records.','small'),
              p('Execution status / all attempts','h2')]
    if model['status_counts']:
        story += [BarChart(model['status_counts'].items())]
    else:
        story += [p('No runs recorded.','small')]
    if model['runs']:
        data=[['PLUGIN','STATUS','ROWS']]
        for r in model['runs']:
            data.append([short_plugin(r['plugin']),r['status'].replace('_',' '),str(r.get('rows',0))])
        story += [p('Run inventory','h2'),table(data,[width-165,110,55],True),p('Full plugin names, run identifiers and execution metadata are retained in the HTML report and CSV.','small')]
    story += [CondPageBreak(180),p('Recovered observables','h2'),
              p('Automatically extracted strings, not confirmed malicious IOCs. No reputation lookups or outbound connections were made by the extractor.')]
    if model['observable_categories']:
        story += [BarChart(model['observable_categories'].items())]
    else:
        story += [p('No candidate observable strings were recovered. This is not evidence of a clean system.','small')]
    if model['observable_preview']:
        data=[['TYPE / SOURCE','VALUE','MATCHED RECORDS']]
        for r in model['observable_preview'][:12]:
            text=r['value']
            if len(text)>320:
                text=text[:320]+' [truncated in PDF; full value in CSV]'
            data.append([r['kind']+'\n'+short_plugin(r['plugin'])+' / row '+str(r['row_id']),text,str(r['occurrences'])])
        story += [p(f'Showing {min(12,len(model["observable_preview"]))} of {model["observable_total"]:,} distinct values. All values and first-source run IDs are in observables.csv.','small'),
                  table(data,[150,width-215,65],True)]
    if model['failures']:
        story += [p('Diagnostics / incomplete coverage','h2')]
        for failure in model['failures'][:12]:
            story += [p(short_plugin(failure['plugin']),'h3'),p(failure['title'])]
            for text in failure['messages'][:3]:
                story.append(p(text[:700],'small'))
        if len(model['failures'])>12:
            story.append(p('Additional diagnostics are included in the HTML report.','small'))
    story += [p('Recommended next actions','h2')]
    for i,text in enumerate(model['recommendations'],1):
        story.append(p(f'{i}. {text}'))
    story += [p('Interpretation limits','h2'),p(model['limits'])]
    if model['notes']:
        story += [p('Analyst notes and bookmarks','h2')]
    for note in model['notes'][:30]:
        story += [p(note['utc']+' / '+note['analyst'],'h3'),p(note['text'][:3000]+(' [continued in HTML report]' if len(note['text'])>3000 else ''))]
    if len(model['notes'])>30:
        story.append(p('Additional notes are included in the HTML report.','small'))
    with binary_output(case,destination) as temporary:
        doc=SimpleDocTemplate(temporary,pagesize=A4,leftMargin=44,rightMargin=44,topMargin=68,bottomMargin=52,
                              title='Test Subject 007 | '+model['case']['name'],author=model['case']['analyst'])
        flow=[]
        for item in story:
            if isinstance(item,Paragraph) and item.style.name in ('h2','h3'):
                flow.append(CondPageBreak(85 if item.style.name=='h2' else 55))
            flow.append(item)
        doc.build(flow,onFirstPage=page,onLaterPages=page)


def write_case_csv(case, destination, model, cancel=None):
    fields=[]
    for run in model['runs']:
        columns,_,_=query_rows(case.root/'runs'/run['id']/'results.sqlite',limit=1)
        if columns and columns[0]=='TreeDepth':
            for col in columns:
                if col not in fields:
                    fields.append(col)
    # Namespace artifact column names to prevent a plugin header colliding with provenance.
    meta=['Record type','Plugin','Run status','Run ID','Row number','Diagnostic']
    with export_stream(case,destination) as out:
        writer=csv.writer(out,lineterminator='\n')
        writer.writerow(meta+[safe_csv_cell('Data: '+s) for s in fields])
        for run in model['runs']:
            total=0
            folder=case.root/'runs'/run['id']
            columns,_,_=query_rows(folder/'results.sqlite',limit=1)
            if columns and columns[0]=='TreeDepth':
                for row_id,row in iter_rows(folder/'results.sqlite'):
                    if cancel and cancel.is_set():
                        raise Cancelled('CSV export cancelled.')
                    writer.writerow([safe_csv_cell(v) for v in ['artifact',run['plugin'],run['status'],run['id'],row_id,'']+[row.get(f,'') for f in fields]])
                    total+=1
            if not total:
                reason=diagnostic_title(run,folder)
                writer.writerow([safe_csv_cell(v) for v in ['run_status',run['plugin'],run['status'],run['id'],'',reason]]+['']*len(fields))
        if not model['runs']:
            writer.writerow(['run_status','','not_analyzed','','','No analysis has been run.']+['']*len(fields))


def diagnostic_title(run,folder):
    from .diagnostics import diagnose
    if run['status'] in ('completed','completed_with_warnings'):
        return 'Completed with zero indexed records; not a clean-system verdict.'
    return diagnose(run,folder)['title']


def write_observables_csv(case,destination,cancel=None):
    with export_stream(case,destination) as out:
        writer=csv.writer(out,lineterminator='\n')
        writer.writerow(['Type','Value','Matched records','Interpretation','First plugin','First run ID','First row number'])
        database=case.root/'observables.sqlite'
        if database.exists():
            with closing(sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True)) as db:
                for row in db.execute('SELECT kind,value,occurrences,note,plugin,run_id,row_id FROM observables ORDER BY kind,value'):
                    if cancel and cancel.is_set():
                        raise Cancelled('Observable export cancelled.')
                    writer.writerow([safe_csv_cell(v) for v in row])


def export_bundle(case, directory, cancel=None, emit=lambda *_: None):
    directory=user_path(directory)
    # Check the chosen parent before creating any report directory.
    safe_destination(case,directory/'destination-check.txt')
    stamp=utc_now().replace(':','').replace('-','').replace('+0000','Z')
    folder=directory/(slug(case.metadata['name'])+'-'+stamp+'-'+uuid.uuid4().hex[:6])
    folder.mkdir(mode=0o700)
    marker=folder/'INCOMPLETE.txt'
    marker.write_text('Report generation is not complete. Do not treat partial files as a complete export.\n',encoding='utf-8')
    paths={kind:folder/name for kind,name in [('pdf','report.pdf'),('html','report.html'),('csv','results.csv'),('observables','observables.csv')]}
    try:
        model=build_summary(case,cancel,emit)
        for kind,function in [('csv',write_case_csv),('html',write_html),('pdf',write_pdf)]:
            if cancel and cancel.is_set():
                raise Cancelled('Export cancelled. Partial files are marked INCOMPLETE.')
            emit('status','Creating '+kind.upper()+' report...')
            if kind=='csv':
                function(case,paths[kind],model,cancel)
            else:
                function(case,paths[kind],model)
        write_observables_csv(case,paths['observables'],cancel)
        paths.update(export_detail_files(case,folder,model))
        digest={str(p.name):hash_file(p,cancel) for p in paths.values()}
        (folder/'SHA256SUMS.txt').write_text(''.join(f'{v}  {k}\n' for k,v in digest.items()),encoding='utf-8')
        atomic_json(case.root/'analysis-summary.json',model)
        case.audit('report_bundle_exported',{'folder':str(folder),'files':digest,'audit_head_in_report':model['audit_head'],'paths':{k:str(v) for k,v in paths.items()}})
        case.metadata['last_exports']={k:str(v) for k,v in paths.items()}
        case.metadata['export_directory']=str(directory)
        case.save()
        marker.unlink()
        return {'folder':str(folder),'paths':{k:str(v) for k,v in paths.items()},'summary':model}
    except Exception as exc:
        marker.write_text('INCOMPLETE EXPORT\n'+str(exc)+'\n',encoding='utf-8')
        raise RuntimeError(f'Report generation was not completed: {exc}\nPartial files (marked INCOMPLETE): {folder}') from exc


def recover_last_exports(case):
    """Recover prior export paths, including cases made by the HTML-only app."""
    paths=dict(case.metadata.get('last_exports',{}))
    audit=case.root/'audit.jsonl'
    if not audit.is_file():
        return paths
    with audit.open(encoding='utf-8') as stream:
        for line in stream:
            event=json.loads(line)
            detail=event.get('detail',{})
            if event.get('action')=='report_bundle_exported' and detail.get('folder'):
                folder=Path(detail['folder'])
                paths=detail.get('paths') or {kind:str(folder/name) for kind,name in [('pdf','report.pdf'),('html','report.html'),('csv','results.csv'),('observables','observables.csv')]}
            elif event.get('action') in ('report_exported','results_exported') and detail.get('destination'):
                path=Path(detail['destination'])
                paths={path.suffix.lower().lstrip('.') or 'file':str(path)}
    return paths
