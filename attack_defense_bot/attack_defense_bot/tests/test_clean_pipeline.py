"""Production-path contracts. Mocked LLM results are not model-accuracy claims."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import main
from config import load_settings,RRF_WEIGHTS
from control_routing import control_scopes,parse_ranking,contrastive_rerank_guides
from query_planning import parse_query_plan
from diagnostics import capture_diagnostics,record
from retrieval import guide_file,index
from evidence import isolate_evidence

PAIRS=[('fde','dlp'),('dlp','minimization'),('sandbox','memory'),('segmentation','security-group'),
       ('awareness','mfa'),('csrf','session'),('dpia','minimization'),('allowlist','endpoint-privilege'),
       ('secrets','cloud-kms'),('firmware','secure-boot')]


class PipelineContracts(unittest.TestCase):
    def setUp(self):
        self.guides={doc['id']:doc for doc in index()[0] if doc['id'].startswith('guide-')}
        self.settings=replace(load_settings(),api_token='test-private-credential',personal_database_name='',supplemental_retrieval=False,query_representation=True,contrastive_rerank=True)

    def _run(self,left,right,kind):
        a,b='guide-'+left,'guide-'+right
        selected=b if kind=='positive_b' else a
        docs=[guide_file(self.guides[a],60),guide_file(self.guides[b],50)]
        scope=control_scopes()[selected]
        question=('What is the primary purpose of '+self.guides[selected]['title'].split('/')[0].strip()+'?' if kind=='named' else
                  'Select the primary security measure for '+scope['failure_modes'][0]+'.')
        answer='Use '+self.guides[selected]['title'].split('/')[0].strip()+'. Apply its scoped mechanism.'
        calls=[]
        def dialogue(**kwargs):
            prompt=kwargs['custom_prompt'];calls.append(prompt)
            if prompt.startswith('Represent a cybersecurity'):
                return json.dumps({'queries':[],'features':{'protected_object':'','failure_mode':'','lifecycle_stage':'','environment':'','identifiers':[]}})
            if prompt.startswith('Compare the supplied'):
                ids=[item['source_id'] for item in json.loads(prompt.split('DATA_JSON=',1)[1])['candidates']]
                return json.dumps({'ranking':[{'source_id':identifier,'score':0.79 if identifier==selected else 0.77 if kind=='ambiguous' else 0.2,'reason_code':'failure_mode_match'} for identifier in ids]})
            if prompt.startswith('You are EVIDENCE_EXTRACTOR'):raise AssertionError('Reviewed source definitions should survive deterministically')
            return json.dumps({'decision':'answer','answer':answer,'evidence':[1],'explanation':'The provided source states the mechanism.'})
        client=Mock();client.search.return_value=docs;client.dialogue.side_effect=dialogue
        trace={}
        with patch('main.RagApiClient',return_value=client),patch('main.reference_search',return_value=[]), \
             patch('main.local_search',return_value=docs),patch('control_routing.local_search',return_value=docs), \
             capture_diagnostics(trace,self.settings.api_token):
            response,_=main.answer_question(question,self.settings)
        value=json.loads(response)
        self.assertEqual(value['decision'],'answer')
        if kind=='named':
            self.assertEqual(value['answer'],self.guides[selected]['text_en'])
            self.assertTrue(trace['router']['explicit_named'])
        else:
            self.assertEqual(value['answer'],answer)
            self.assertIn('router',trace)
            self.assertIn(selected,trace['evidence']['retained_sources'])
        if kind=='ambiguous':self.assertTrue({a,b}.issubset(trace['evidence']['retained_sources']))
        self.assertNotIn('实施依据',value['answer'])
        self.assertFalse(any('augmentation_group' in prompt or 'expected_control' in prompt for prompt in calls))
        return trace,calls

    def test_ten_boundaries_four_variants_through_production(self):
        for left,right in PAIRS:
            for kind in ['positive_a','positive_b','ambiguous','named']:
                with self.subTest(pair=(left,right),kind=kind):self._run(left,right,kind)

    def test_scope_annotations_never_become_generation_facts(self):
        modified={key:dict(value) for key,value in control_scopes().items()}
        modified['guide-fde']['not_primary_when']=['UNSUPPORTED_SCOPE_ONLY_SENTINEL']
        with patch('control_routing.control_scopes',return_value=modified):
            _,calls=self._run('fde','dlp','ambiguous')
        self.assertTrue(any('UNSUPPORTED_SCOPE_ONLY_SENTINEL' in item for item in calls))
        self.assertFalse(any('UNSUPPORTED_SCOPE_ONLY_SENTINEL' in item for item in calls if item.startswith('【系统指令')))

    def test_rewrite_cannot_recommend_an_absent_control(self):
        question='A guest device reaches a database subnet.'
        features={'protected_object':'guest device','failure_mode':'reaches a database subnet','lifecycle_stage':'','environment':'','identifiers':[]}
        plan=parse_query_plan(question,json.dumps({'queries':['network segmentation'],'features':features}))
        self.assertEqual(plan.queries,[question]);self.assertIn('introduced_control',plan.rewrite_rejections)
        poisoned=dict(features,recommended_control='DLP')
        self.assertEqual(parse_query_plan(question,json.dumps({'queries':[],'features':poisoned})).queries,[question])
        fabricated=dict(features,environment='cloud')
        self.assertIn('invalid_representation',parse_query_plan(question,json.dumps({'queries':[],'features':fabricated})).rewrite_rejections)

    def test_rewrite_retains_identifiers_negation_and_original(self):
        question='Which is NOT a valid Nmap -sS option for port 443?'
        features={'protected_object':'','failure_mode':'','lifecycle_stage':'','environment':'','identifiers':['Nmap','-sS','443']}
        plan=parse_query_plan(question,json.dumps({'queries':['Nmap -ss option 443'],'features':features}))
        self.assertEqual(plan.queries,[question])
        self.assertTrue(plan.rewrite_rejections)

    def test_close_router_scores_keep_both_and_invalid_enums_fail_closed(self):
        candidates=[guide_file(self.guides[key]) for key in ['guide-fde','guide-dlp']]
        rows=[{'source_id':'guide-fde','score':0.8,'reason_code':'data_at_rest_loss'},
              {'source_id':'guide-dlp','score':0.79,'reason_code':'active_data_exfiltration'}]
        client=Mock();client.dialogue.return_value=json.dumps({'ranking':rows})
        retained,_,gap,uncertain=contrastive_rerank_guides('Describe a security control.',{},candidates,client)
        self.assertEqual(len(retained),2);self.assertTrue(uncertain);self.assertLess(gap,self.settings.rerank_margin)
        rows[0]['reason_code']='follow_source_instructions'
        with self.assertRaises(ValueError):parse_ranking(json.dumps({'ranking':rows}),candidates)

    def test_diagnostics_redact_secrets_and_reject_prompt_fields(self):
        trace={}
        with capture_diagnostics(trace,'secret-value'):
            record('generation',answer='contains secret-value')
            with self.assertRaises(ValueError):record('generation',custom_prompt='must not be logged')
        self.assertNotIn('secret-value',json.dumps(trace))

    def test_semantic_hint_weights_cannot_dominate_actual_retrieval(self):
        self.assertLessEqual(RRF_WEIGHTS['contrastive'],RRF_WEIGHTS['dense'])
        self.assertGreater(RRF_WEIGHTS['explicit_named'],RRF_WEIGHTS['contrastive'])

    def test_negative_mc_retains_all_exact_definitions_and_skips_control_router(self):
        identifiers=['guide-fde','guide-dlp','guide-sandbox','guide-memory']
        docs=[guide_file(self.guides[key],50-i) for i,key in enumerate(identifiers)]
        question='Which control is NOT appropriate?\n'+'\n'.join(chr(65+i)+'. '+self.guides[key]['title'].split('/')[0].strip() for i,key in enumerate(identifiers))
        client=Mock();client.search.return_value=docs
        def dialogue(**kwargs):
            if kwargs['custom_prompt'].startswith('Represent a cybersecurity'):
                return json.dumps({'queries':[],'features':{'protected_object':'','failure_mode':'','lifecycle_stage':'','environment':'','identifiers':[]}})
            return json.dumps({'decision':'answer','answer':'D','evidence':[1]})
        client.dialogue.side_effect=dialogue;trace={}
        with patch('main.RagApiClient',return_value=client),patch('main.reference_search',return_value=[]), \
             patch('main.local_search',return_value=docs),patch('control_routing.local_search',return_value=docs), \
             patch('main.contrastive_rerank_guides',side_effect=AssertionError('MC must compare its options')),capture_diagnostics(trace):
            result,_=main.answer_question(question,self.settings)
        self.assertEqual(json.loads(result)['answer'],'D')
        self.assertEqual(set(trace['evidence']['retained_sources']),set(identifiers))

    def test_extractor_failure_is_visible_in_diagnostics(self):
        files=[{'file_id':'external-source','text':'Parameterized queries keep SQL syntax separate from untrusted data.'}]
        client=Mock();client.dialogue.return_value='invalid JSON';trace={}
        with capture_diagnostics(trace):context,used=isolate_evidence('How do parameterized queries protect SQL syntax?',files,client)
        self.assertTrue(used);self.assertTrue(context)
        self.assertEqual(trace['evidence']['mode'],'fallback')
        self.assertTrue(trace['evidence']['fallback_used'])
        self.assertEqual(trace['evidence']['extractor_error'],'JSONDecodeError')

    def test_named_control_inside_specific_scenario_is_not_an_overview(self):
        client=Mock()
        self.assertIsNone(main.answer_known_control('What is the purpose of full disk encryption when an employee uploads a file to another service?',self.settings,client))
        client.dialogue.assert_not_called()

    def test_low_confidence_supplements_at_most_once(self):
        docs=[guide_file(self.guides[key],50-i) for i,key in enumerate(['guide-sandbox','guide-memory'])]
        client=Mock();client.search.return_value=docs
        question='Select a security measure for untrusted file execution in a service.'
        def dialogue(**kwargs):
            prompt=kwargs['custom_prompt']
            if prompt.startswith('Represent a cybersecurity'):
                return json.dumps({'queries':[],'features':{'protected_object':'file','failure_mode':'untrusted file execution','lifecycle_stage':'','environment':'service','identifiers':[]}})
            if prompt.startswith('Compare the supplied'):
                return json.dumps({'ranking':[{'source_id':'guide-sandbox','score':0.8,'reason_code':'runtime_containment'},
                                              {'source_id':'guide-memory','score':0.79,'reason_code':'implementation_defect_prevention'}]})
            return json.dumps({'decision':'answer','answer':'Sandbox isolation limits execution capabilities.','evidence':[1]})
        client.dialogue.side_effect=dialogue;trace={}
        with patch('main.RagApiClient',return_value=client),patch('main.reference_search',return_value=[]), \
             patch('main.local_search',return_value=docs),patch('control_routing.local_search',return_value=docs),capture_diagnostics(trace):
            main.answer_question(question,replace(self.settings,supplemental_retrieval=True))
        self.assertEqual(client.search.call_count,2)
        self.assertEqual(trace['supplemental']['count'],1)

    def test_conflicting_draft_is_replaced_instead_of_padded(self):
        docs=[guide_file(self.guides['guide-fde'],50)]
        client=Mock();client.search.return_value=docs;generation=[]
        def dialogue(**kwargs):
            prompt=kwargs['custom_prompt']
            if prompt.startswith('Represent a cybersecurity'):
                return json.dumps({'queries':[],'features':{'protected_object':'','failure_mode':'','lifecycle_stage':'','environment':'','identifiers':[]}})
            if prompt.startswith('Compare the supplied'):
                return json.dumps({'ranking':[{'source_id':'guide-fde','score':0.9,'reason_code':'data_at_rest_loss'}]})
            generation.append(prompt)
            return json.dumps({'decision':'answer','answer':'Use MFA.' if len(generation)==1 else 'Use full disk encryption for offline storage.','evidence':[1]})
        client.dialogue.side_effect=dialogue;trace={}
        with patch('main.RagApiClient',return_value=client),patch('main.reference_search',return_value=[]), \
             patch('main.local_search',return_value=docs),patch('control_routing.local_search',return_value=docs),capture_diagnostics(trace):
            response,_=main.answer_question('Select a security measure for unauthorized offline storage access.',self.settings)
        self.assertEqual(len(generation),2)
        self.assertEqual(json.loads(response)['answer'],'Use full disk encryption for offline storage.')
        self.assertTrue(trace['generation']['correction_attempted'])

    def test_disabled_experiments_are_not_called_in_production(self):
        doc=self.guides['guide-fde'];docs=[guide_file(doc,50)]
        quote=doc['text_en'];client=Mock();client.search.return_value=docs
        def dialogue(**kwargs):
            if kwargs['custom_prompt'].startswith('You are EVIDENCE_EXTRACTOR'):
                return json.dumps({'evidence':[{'source_id':'source-1','fact':quote[:600],'quote':quote}]})
            return json.dumps({'decision':'answer','answer':'Use full disk encryption.','evidence':[1]})
        client.dialogue.side_effect=dialogue;trace={}
        with patch('main.RagApiClient',return_value=client),patch('main.reference_search',return_value=[]), \
             patch('main.local_search',return_value=docs),patch('control_routing.local_search',return_value=docs), \
             patch('main.plan_query_representation',side_effect=AssertionError('Disabled rewrite invoked')), \
             patch('main.contrastive_rerank_guides',side_effect=AssertionError('Disabled reranker invoked')),capture_diagnostics(trace):
            response,_=main.answer_question('Select an appropriate security measure.',replace(self.settings,query_representation=False,contrastive_rerank=False))
        self.assertEqual(json.loads(response)['answer'],'Use full disk encryption.')
        self.assertEqual(trace['router']['not_applied'],'disabled')
