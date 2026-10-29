import sys
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'v28'))
from select_profile import choose_profile
from semantic_evaluator import failure_stage
sys.path.insert(0,str(Path(__file__).resolve().parent))
import finalize


def row(semantic=.9,primary=.9,recall=.9):
    return {'final_semantic_accuracy':semantic,'target_control_accuracy':primary,
            'candidate_recall':{'3':recall},'attack_recall':1.0,'benign_false_reject_rate':0.0,'error_count':0}


class ReleaseTests(unittest.TestCase):
    def test_better_control_classification_cannot_mask_worse_answers(self):
        self.assertEqual(choose_profile({'A':row(.9,.9),'H3':row(.8,1.0)})['selected_variant'],'A')

    def test_tie_preserves_baseline(self):
        self.assertEqual(choose_profile({'A':row(),'H3':row()})['selected_variant'],'A')

    def test_recall_and_safety_remain_release_gates(self):
        for candidate in [row(1.0,1.0,.8),dict(row(1.0,1.0),attack_recall=.99),dict(row(1.0,1.0),benign_false_reject_rate=.01)]:
            self.assertEqual(choose_profile({'A':row(),'H3':candidate})['selected_variant'],'A')

    def test_valid_improvement_is_eligible(self):
        self.assertEqual(choose_profile({'A':row(),'H3':row(1.0,1.0)})['selected_variant'],'H3')

    def test_no_reranker_cannot_be_blamed_for_fusion_loss(self):
        trace={'retrieval':{'candidate_sources':['guide-dlp']},'router':{'ranking':[]},'fusion':{'sources':[]}}
        e={'expected_control':'guide-dlp','final_semantic_correct':False,'target_control_correct':True}
        self.assertEqual(failure_stage(trace,e),'fusion_loss')

    def test_stage_losses_are_separate(self):
        e={'expected_control':'guide-dlp','final_semantic_correct':False,'target_control_correct':True}
        trace={'retrieval':{'candidate_sources':['guide-dlp']},'router':{'ranking':[]},'fusion':{'sources':['guide-dlp']},'prepared':{'sources':['guide-dlp']},'evidence':{'retained_sources':[]}}
        self.assertEqual(failure_stage(trace,e),'evidence_extraction_miss')
        trace['evidence']['retained_sources']=['guide-dlp']
        self.assertEqual(failure_stage(trace,e),'generation_incomplete')
        trace['prepared']['sources']=[]
        self.assertEqual(failure_stage(trace,e),'context_loss')

    def test_holdout_veto_cannot_select_a_different_holdout_winner(self):
        validation={key:dict(row(),scorer_sha256='same',source_state={}) for key in ['A','H','H1','H2','H3']}
        holdout={key:dict(value) for key,value in validation.items()}
        holdout['H3'].update(final_semantic_accuracy=.8)
        holdout['H2'].update(final_semantic_accuracy=1.0)
        with tempfile.TemporaryDirectory(prefix='release-veto-') as tmp:
            root=Path(tmp);here=root/'experiment';(here/'results').mkdir(parents=True)
            (root/'attack_defense_bot/attack_defense_bot').mkdir(parents=True)
            fixtures={'selection.json':{'selected_variant':'H3','baseline_checks':{}},
                      'safety_audit.json':{'attack_recall':1.0,'benign_guard_false_reject_rate':0.0,'guard_unchanged':True},
                      'tests.json':{'successful':True}}
            with patch.object(finalize,'ROOT',root),patch.object(finalize,'HERE',here), \
                 patch.object(finalize,'summaries',side_effect=lambda split:validation if split=='validation' else holdout), \
                 patch.object(finalize,'read',side_effect=lambda name:fixtures[name]),patch.object(finalize,'inference_fingerprint',return_value='same'),patch('builtins.print'):
                finalize.release()
            decision=json.loads((here/'results/release_decision.json').read_text())
            self.assertFalse(decision['new_candidate_release_allowed'])
            self.assertFalse(decision['holdout_used_to_reselect'])
            self.assertEqual(decision['default_variant'],'A')


if __name__=='__main__':unittest.main()
