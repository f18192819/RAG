import hashlib
import json
from pathlib import Path
import unittest
from semantic_evaluator import evaluate,predicted_primary,aggregate


class StrictEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.row={'input':{'text':'Which measure should take priority?'},'expected':{'decision':'answer','answer':'数据防泄漏阻止未经授权外发。',
            'concepts':[['数据防泄漏','DLP'],['未经授权外发','未授权传输']]},'provenance':{'augmentation_group':'offline-example'}}
        self.canonical={'offline-example':'guide-dlp'}
        self.trace={'retrieval':{'candidate_sources':['guide-dlp']},'router':{'ranking':[{'source_id':'guide-dlp'}]},
                    'fusion':{'sources':['guide-dlp']},'prepared':{'sources':['guide-dlp']},'evidence':{'retained_sources':['guide-dlp']}}

    def test_wrong_primary_cannot_pass_by_appending_correct_guide(self):
        response={'decision':'answer','answer':'应优先采用数据最小化。\n\n实施依据 [1]：数据防泄漏可阻止未经授权外发。'}
        score=evaluate(self.row,response,self.trace,self.canonical)
        self.assertEqual(score['predicted_control'],'guide-minimization')
        self.assertFalse(score['target_control_correct']);self.assertFalse(score['final_semantic_correct'])
        self.assertIsNone(score['mechanism_coverage'])

    def test_later_mention_does_not_replace_primary(self):
        self.assertEqual(predicted_primary('应优先采用MFA，同时安全意识培训也很重要。'),'guide-mfa')

    def test_primary_precedes_mechanism_scoring(self):
        incomplete=evaluate(self.row,{'decision':'answer','answer':'应优先采用数据防泄漏。'},self.trace,self.canonical)
        complete=evaluate(self.row,{'decision':'answer','answer':'应优先采用数据防泄漏，阻止未经授权外发。'},self.trace,self.canonical)
        self.assertTrue(incomplete['target_control_correct']);self.assertFalse(incomplete['final_semantic_correct'])
        self.assertTrue(complete['final_semantic_correct'])

    def test_unresolved_primary_is_not_credited(self):
        score=evaluate(self.row,{'decision':'answer','answer':'应加强数据、访问、风险、验证、保护、权限和监测。'},self.trace,self.canonical)
        self.assertTrue(score['primary_unresolved']);self.assertFalse(score['final_semantic_correct'])
        self.assertIsNone(predicted_primary('Prioritize data, access, security, risk and monitoring.'))

    def test_stage_survival_distinguishes_evidence_drop(self):
        trace={**self.trace,'evidence':{'retained_sources':[]}}
        score=evaluate(self.row,{'decision':'answer','answer':'应优先采用MFA。'},trace,self.canonical)
        self.assertEqual(score['failure_stage'],'evidence_drop')
        self.assertTrue(score['source_survival']['retrieval']);self.assertFalse(score['source_survival']['evidence'])

    def test_split_integrity_and_control_disjointness(self):
        root=Path(__file__).resolve().parents[2]
        manifest=json.loads((root/'experiments/v28/splits.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['dataset_sha256'],hashlib.sha256((root/'public_dataset.jsonl').read_text(encoding='utf-8').encode('utf-8')).hexdigest())
        rows={row['id']:row for row in [json.loads(line) for line in (root/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]}
        sets=[]
        for ids in manifest['partitions'].values():
            sets.append({manifest['canonical_controls'][rows[key]['provenance']['augmentation_group']] for key in ids})
        self.assertFalse(sets[0]&sets[1]);self.assertFalse(sets[0]&sets[2]);self.assertFalse(sets[1]&sets[2])

if __name__=='__main__':unittest.main()
