"""Select-all regression fixtures, including the exact --source failure shape.

These test the planner with synthetic catalogs, not real memory analysis.
"""
from __future__ import annotations
import csv
import json
import tempfile
import unittest
from pathlib import Path
from test_subject_007.options import plugin_arguments, validate_options, PluginOptionsError
from test_subject_007.planning import build_plan
from test_subject_007.profiles import COMPLETE, COMPLETE_WINDOWS, DESCRIPTIONS, default_jobs, resolve
from test_subject_007.case import Case
from test_subject_007.results import index_csv
from test_subject_007.summary import build_summary
from test_subject_007.reports import export_bundle
from test_subject_007.util import atomic_json, utc_now


def spec(name, kind='str', required=False, default=None, **kw):
    return dict(name=name, flag='--'+name.replace('_','-'), kind=kind,
                required=required, default=default, description=name, **kw)


def plugin(name, *opts):
    return {'name':name, 'options':list(opts), 'description':'Synthetic plugin requirements'}


def fixture_catalog(count=105):
    values = [plugin('windows.info.Info'), plugin('windows.pslist.PsList', spec('pid','list',element_type='int')),
              plugin('windows.pe_symbols.PESymbols', spec('source','choice',True,choices=['kernel','processes']),
                     spec('module',required=True), spec('symbols','list',element_type='str'), spec('addresses','list',element_type='int')),
              plugin('windows.pedump.PEDump', spec('base','int',True), spec('pid','list',element_type='int'), spec('kernel_module','bool',default=False)),
              plugin('windows.strings.Strings', spec('strings_file',required=True,is_file=True)),
              plugin('windows.vadyarascan.VadYaraScan', spec('yara_file',is_file=True), spec('yara_string'))]
    values += [plugin(f'windows.fixture{i}.Synthetic') for i in range(count-len(values))]
    return {'version':'SYNTHETIC','unavailable':[], 'plugins':values}


class PlannerTests(unittest.TestCase):
    def test_105_checked_does_not_abort_on_source(self):
        cat=fixture_catalog()
        plan=build_plan(cat,[p['name'] for p in cat['plugins']],{},'Custom','Windows')
        self.assertEqual(len(plan.selected),105)
        self.assertEqual(len(plan.items),101)
        self.assertEqual(len(plan.deferred),4)
        problem=next(d for d in plan.deferred if d['plugin']=='windows.pe_symbols.PESymbols')
        self.assertIn('--source',problem['reason']); self.assertIn('--module',problem['reason'])
        self.assertEqual(plan.items[0][0]['name'],'windows.info.Info')

    def test_specialist_becomes_ready_when_its_inputs_are_configured(self):
        cat=fixture_catalog()
        saved={'windows.pe_symbols.PESymbols':{'source':'processes','module':'ntdll.dll','symbols':'NtCreateFile'}}
        plan=build_plan(cat,saved,saved,'Custom','Windows')
        self.assertFalse(plan.deferred)
        self.assertEqual(plan.items[0][1],['--source','processes','--module','ntdll.dll','--symbols','NtCreateFile'])

    def test_unconfigured_does_not_gain_an_invented_source(self):
        p=fixture_catalog()['plugins'][2]
        args,problems=validate_options(p,{})
        self.assertNotIn('--source',args);self.assertTrue(problems)

    def test_all_errors_name_the_plugin(self):
        p=fixture_catalog()['plugins'][2]
        with self.assertRaises(PluginOptionsError) as result:plugin_arguments(p,{})
        self.assertIn(p['name'],str(result.exception))
        self.assertGreaterEqual(len(result.exception.problems),2)

    def test_defaults_are_honored_but_no_first_choice_is_guessed(self):
        p=plugin('windows.example.Example',spec('count','int',True,0),spec('mode','choice',True,choices=['a','b']))
        args,issues=validate_options(p,{})
        self.assertEqual(args,['--count','0']);self.assertIn('--mode',issues[0])

    def test_false_optional_checkbox_remains_off(self):
        p=plugin('windows.pslist.PsList',spec('dump','bool',default=False))
        self.assertEqual(plugin_arguments(p,{'dump':False}),[])
        self.assertEqual(plugin_arguments(p,{'dump':'False'}),[])

    def test_required_boolean_matches_required_cli_flag(self):
        p=plugin('windows.test.Test',spec('agree','bool',True,False))
        self.assertTrue(validate_options(p,{})[1])
        self.assertEqual(plugin_arguments(p,{'agree':True}),['--agree'])

    def test_integer_and_lists_accept_hex_and_leading_zeroes(self):
        p=plugin('windows.test.Test',spec('offset','int'),spec('pid','list',element_type='int',max_elements=0))
        self.assertEqual(plugin_arguments(p,{'offset':'0x4000','pid':'["004", "0x80"]'}),['--offset','16384','--pid','4','128'])

    def test_list_issues_do_not_crash_remaining_plan(self):
        cat={'plugins':[plugin('windows.pslist.PsList',spec('pid','list',element_type='int')),plugin('windows.info.Info')]}
        plan=build_plan(cat,['windows.pslist.PsList','windows.info.Info'],{'windows.pslist.PsList':{'pid':'[broken'}},'Custom','Windows')
        self.assertEqual(len(plan.items),1);self.assertEqual(len(plan.deferred),1)

    def test_file_input_with_spaces_and_file_uri(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'strings with spaces.txt';path.write_text('123 example\n')
            p=fixture_catalog()['plugins'][4]
            for value in (str(path),path.as_uri()):
                self.assertEqual(plugin_arguments(p,{'strings_file':value}),['--strings-file',str(path.resolve())])

    def test_missing_input_file_is_deferred(self):
        p=fixture_catalog()['plugins'][4]
        self.assertIn('does not exist',validate_options(p,{'strings_file':'/missing/nowhere.txt'})[1][0])

    def test_remote_input_is_not_fetched_during_preflight(self):
        p=fixture_catalog()['plugins'][4]
        self.assertIn('local input',validate_options(p,{'strings_file':'https://example.invalid/strings'})[1][0])

    def test_pedump_requires_target_and_exclusive_address_space(self):
        p=fixture_catalog()['plugins'][3]
        self.assertTrue(validate_options(p,{'base':'0x1000'})[1])
        self.assertTrue(validate_options(p,{'base':'0x1000','pid':'4','kernel_module':True})[1])
        self.assertFalse(validate_options(p,{'base':'0x1000','pid':'4'})[1])

    def test_empty_list_string_is_not_a_target(self):
        p=fixture_catalog()['plugins'][3]
        self.assertTrue(validate_options(p,{'base':'0x1000','pid':'[]'})[1])
        self.assertFalse(validate_options(p,{'base':'0x1000','pid':'4','kernel_module':'False'})[1])
        p=fixture_catalog()['plugins'][2]
        self.assertTrue(validate_options(p,{'source':'kernel','module':'nt','symbols':'[]'})[1])

    def test_yara_needs_an_actual_rule_input(self):
        p=fixture_catalog()['plugins'][5]
        self.assertTrue(validate_options(p,{})[1])
        self.assertFalse(validate_options(p,{'yara_string':'sample'})[1])

    def test_complete_profile_is_explicit_broad_and_not_dump_everything(self):
        self.assertIn(COMPLETE,DESCRIPTIONS)
        self.assertGreater(len(COMPLETE_WINDOWS),40)
        self.assertIn('windows.filescan',COMPLETE_WINDOWS)
        self.assertIn('windows.registry.hivescan',COMPLETE_WINDOWS)
        for candidate in COMPLETE_WINDOWS:
            self.assertFalse(any(word in candidate for word in ['hashdump','lsadump','cachedump','pedump','pe_symbols','strings','yarascan','dumpfiles']))

    def test_complete_preset_selects_all_declared_installed_and_expands_keys(self):
        plugins=[]
        for candidate in COMPLETE_WINDOWS:
            module=candidate.split('|')[0]
            name=module if module.split('.')[-1][0].isupper() else module+'.Fixture'
            opts=[spec('key')] if '.printkey.' in name else []
            plugins.append(plugin(name,*opts))
        cat={'plugins':plugins}
        selected,missing=resolve(cat,'Windows',COMPLETE)
        self.assertFalse(missing);self.assertEqual(len(selected),len(COMPLETE_WINDOWS))
        plan=build_plan(cat,[p['name'] for p in selected],{},COMPLETE,'Windows')
        self.assertFalse(plan.deferred)
        self.assertEqual(len(plan.items),len(selected)+3)

    def test_complete_unknown_os_is_explicit_not_a_fake_banners_preset(self):
        selected,missing=resolve(fixture_catalog(),'Unknown',COMPLETE)
        self.assertFalse(selected);self.assertTrue(missing)

    def test_unknown_plugin_and_os_mismatch_are_retained_as_gaps(self):
        cat={'plugins':[plugin('linux.pslist.PsList'),plugin('windows.info.Info')]}
        plan=build_plan(cat,['windows.info.Info','linux.pslist.PsList','windows.missing.Foo'],{},'Custom','Windows')
        self.assertEqual(len(plan.items),1);self.assertEqual(len(plan.deferred),2)

    def test_exact_mft_plugin_is_not_its_ads_sibling(self):
        cat={'plugins':[plugin('windows.mftscan.ADS'),plugin('windows.mftscan.MFTScan')]}
        chosen,_=resolve(cat,'Windows',COMPLETE)
        self.assertEqual([p['name'] for p in chosen],['windows.mftscan.MFTScan'])

    def test_saved_key_overrides_four_key_preset_expansion(self):
        p=plugin('windows.registry.printkey.PrintKey',spec('key'))
        plan=build_plan({'plugins':[p]},[p['name']],{p['name']:{'key':'Custom\\Run'}},COMPLETE,'Windows')
        self.assertEqual(len(plan.items),1)
        self.assertEqual(plan.items[0][1],['--key','Custom\\Run'])

    def test_case_plan_record_roundtrips_without_engine_classes(self):
        plan=build_plan(fixture_catalog(),['windows.pe_symbols.PESymbols','windows.info.Info'],{},'Custom','Windows')
        self.assertEqual(json.loads(json.dumps(plan.record())),plan.record())

    def test_all_blocked_does_not_make_empty_success(self):
        plan=build_plan(fixture_catalog(),['windows.pe_symbols.PESymbols'],{},'Custom','Windows')
        self.assertFalse(plan.items);self.assertEqual(len(plan.deferred),1)


class PlanningReportTests(unittest.TestCase):
    def test_deferred_selection_is_not_reported_as_full_success(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);image=root/'capture.raw';image.write_bytes(b'SYNTHETIC')
            case=Case.create(root/'cases',image,'Synthetic preflight','Test','Windows')
            try:
                folder=case.root/'runs'/'fixture';folder.mkdir()
                (folder/'stdout.csv').write_text('TreeDepth,PID,Process\n0,4,System\n')
                n,columns,error=index_csv(folder/'stdout.csv',folder/'results.sqlite')
                self.assertFalse(error)
                atomic_json(folder/'run.json',{'id':'fixture','plugin':'windows.pslist.PsList','arguments':[],
                    'status':'completed','rows':n,'columns':columns,'started_utc':utc_now(),'error':'','index_error':''})
                plan=build_plan(fixture_catalog(),['windows.pslist.PsList','windows.pe_symbols.PESymbols'],{},'Custom','Windows')
                case.metadata['last_batch']={'preflight':plan.record()};case.metadata['synthetic_fixture']=True;case.save()
                model=build_summary(case)
                self.assertEqual(model['assessment'],'PARTIAL INVESTIGATION COVERAGE')
                self.assertEqual(model['complete_latest'],1)
                self.assertEqual(len(model['planning_gaps']),1)
                result=export_bundle(case,root/'exports')
                html=Path(result['paths']['html']).read_text()
                self.assertIn('Preflight: selected but not run',html)
                self.assertIn('windows.pe_symbols.PESymbols',html)
                with Path(result['paths']['planning']).open() as stream:
                    data=list(csv.DictReader(stream))
                self.assertEqual(len(data),1);self.assertIn('--source',data[0]['reason'])
                self.assertTrue(Path(result['paths']['plan_json']).exists())
                self.assertGreater(Path(result['paths']['pdf']).stat().st_size,1000)
            finally:case.close()
