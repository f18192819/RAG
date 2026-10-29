"""Select against A using final semantic accuracy first, never a forced upgrade."""
import argparse
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent


def nonregression(row, baseline):
    checks={
        'final_semantic':row['final_semantic_accuracy']>=baseline['final_semantic_accuracy'],
        'primary_control':row['target_control_accuracy']>=baseline['target_control_accuracy'],
        'recall_at_3':row['candidate_recall']['3']>=baseline['candidate_recall']['3'],
        'operational_errors':row.get('error_count',0)==0,
        'attack_recall':row.get('attack_recall',1.0)==1.0,
        'benign_false_reject':row.get('benign_false_reject_rate',0.0)==0.0,
    }
    return all(checks.values()),checks


def choose_profile(summaries):
    baseline=summaries['A']
    if baseline.get('error_count',0):raise ValueError('Baseline inference failed; cannot establish a release threshold')
    eligible=['A'];checks={}
    for key,row in summaries.items():
        if key=='A':continue
        passed,checks[key]=nonregression(row,baseline)
        if passed:eligible.append(key)
    chosen=max(eligible,key=lambda key:(summaries[key]['final_semantic_accuracy'],summaries[key]['target_control_accuracy'],key=='A'))
    return {'selected_variant':chosen,'eligible_profiles':eligible,'baseline_checks':checks,
            'selection_split':'validation','holdout_used_for_selection':False,
            'configuration':summaries[chosen].get('run_configuration',{}),
            'selection_frozen':True,'objective':'final_semantic_accuracy_first'}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--results-dir',type=Path,default=HERE/'results')
    args=parser.parse_args();target=args.results_dir/'selection.json'
    if target.exists():raise SystemExit('Selection already frozen; refusing to tune after holdout.')
    summaries={}
    for path in args.results_dir.glob('*_validation_summary.json'):
        row=json.loads(path.read_text(encoding='utf-8'))
        if not row.get('real_model_inference') or not row.get('strict_scoring_complete'):
            raise SystemExit('All real validation experiments must be strictly scored first.')
        summaries[row['variant']]=row
    selection=choose_profile(summaries)
    target.write_text(json.dumps(selection,indent=2)+'\n',encoding='utf-8')
    profile={'selected_variant':'A','production_profile':'A','query_representation':False,
             'contrastive_rerank':False,'candidate_retention':False,'answer_completeness':False,
             'selection_status':'baseline_until_release_gate_passes'}
    (ROOT/'attack_defense_bot/attack_defense_bot/pipeline_profile.json').write_text(json.dumps(profile,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(selection,indent=2))


if __name__=='__main__':main()
