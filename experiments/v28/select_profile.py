"""One global profile selection from validation only; never inspect holdout."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent


def main():
    target=HERE/'results/selection.json'
    if target.exists():raise SystemExit('Selection already frozen; refusing to tune after holdout.')
    summaries={}
    for key in 'ABCDEFGHI':
        path=HERE/('results/'+key+'_validation_summary.json')
        row=json.loads(path.read_text(encoding='utf-8'))
        if not row.get('real_model_inference') or not row.get('strict_scoring_complete'):
            raise SystemExit('All real validation experiments must be strictly scored first.')
        summaries[key]=row
    baseline=summaries['A']['candidate_recall']['3']
    eligible=[key for key in 'FGHI' if summaries[key]['candidate_recall']['3']>=baseline and not summaries[key]['error_count']]
    candidates=eligible or [key for key in 'FGHI' if not summaries[key]['error_count']]
    if not candidates:raise SystemExit('Every clean profile has operational errors; do not select a corrupted run.')
    chosen=max(candidates,key=lambda key:(summaries[key]['target_control_accuracy'],summaries[key]['final_semantic_accuracy'],{'F':0,'G':1,'I':2,'H':3}[key]))
    selection={'selected_variant':chosen,'retrieval_nonregression_met':bool(eligible),
               'eligible_profiles':eligible,'selection_split':'validation','holdout_used_for_selection':False,
               'configuration':summaries[chosen]['run_configuration'],
               'protocol':'SELECTION_PROTOCOL.md','selection_frozen':True}
    target.write_text(json.dumps(selection,indent=2)+'\n',encoding='utf-8')
    profile={'selected_variant':chosen,**selection['configuration'],'selection_status':'validation_selected'}
    (ROOT/'attack_defense_bot/attack_defense_bot/pipeline_profile.json').write_text(json.dumps(profile,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(selection,indent=2))

if __name__=='__main__':main()
