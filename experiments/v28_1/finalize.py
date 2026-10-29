"""Freeze validation selection; use holdout only as a release veto."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'experiments/v28'),str(ROOT/'tools')]
from select_profile import choose_profile,nonregression
from platform_client import inference_fingerprint


def read(name):return json.loads((HERE/'results'/name).read_text(encoding='utf-8'))


def summaries(split):
    result={key:read(f'{key}_{split}_summary.json') for key in ['A','H','H1','H2','H3']}
    states=[json.dumps(row['source_state'],sort_keys=True) for row in result.values()]
    scorers={row['scorer_sha256'] for row in result.values()}
    logic_keys={'production_profile','query_representation','contrastive_rerank','candidate_retention','answer_completeness'}
    configs={json.dumps({k:v for k,v in row['model_configuration'].items() if k not in logic_keys},sort_keys=True) for row in result.values()}
    if len(set(states))!=1 or len(scorers)!=1 or len(configs)!=1:raise SystemExit('Unequal source, scorer or model configurations; release blocked.')
    if any(not r.get('strict_scoring_complete') or not r.get('real_model_inference') for r in result.values()):raise SystemExit('Real uniformly scored experiments are required.')
    return result


def select():
    target=HERE/'results/selection.json'
    if target.exists():raise SystemExit('Selection already frozen; no reselection.')
    selected=choose_profile(summaries('validation'))
    selected['protocol']='experiments/v28_1/PROTOCOL.md'
    target.write_text(json.dumps(selected,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(selected,indent=2))


def release():
    path=HERE/'results/release_decision.json'
    if path.exists():raise SystemExit('Release decision already exists; refusing to reinterpret holdout.')
    validation=summaries('validation');holdout=summaries('holdout');selection=read('selection.json')
    if validation['A']['scorer_sha256']!=holdout['A']['scorer_sha256'] or validation['A']['source_state']!=holdout['A']['source_state']:
        raise SystemExit('Source/scorer changed between validation and holdout; release blocked.')
    chosen=selection['selected_variant']
    passed,checks=nonregression(holdout[chosen],holdout['A'])
    validation_passed=nonregression(validation[chosen],validation['A'])[0]
    safety=read('safety_audit.json');tests=read('tests.json')
    safe=safety['attack_recall']==1.0 and safety['benign_guard_false_reject_rate']==0.0 and safety['guard_unchanged']
    allowed=chosen!='A' and passed and validation_passed and safe and tests['successful']
    profile={'selected_variant':chosen if allowed else 'A','production_profile':'candidate' if allowed else 'A',
             'query_representation':False,'contrastive_rerank':False,
             'candidate_retention':bool(allowed and chosen in {'H1','H3'}),
             'answer_completeness':bool(allowed and chosen in {'H2','H3'}),
             'selection_status':'validation_and_holdout_passed' if allowed else 'baseline_retained'}
    target=ROOT/'attack_defense_bot/attack_defense_bot/pipeline_profile.json'
    target.write_text(json.dumps(profile,indent=2)+'\n',encoding='utf-8')
    decision={'validation_selected':chosen,'holdout_used_to_reselect':False,'holdout_nonregression_checks':checks,
              'validation_baseline_checks':selection['baseline_checks'],
              'release_reason':'validation_kept_baseline' if chosen=='A' else 'nonregression_passed' if allowed else 'final_confirmation_failed',
              'new_candidate_release_allowed':allowed,'default_variant':profile['selected_variant'],
              'deployed_profile':profile,'package_fingerprint':inference_fingerprint(),
              'platform_uploaded_this_round':False}
    path.write_text(json.dumps(decision,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(decision,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['select','release']);args=parser.parse_args()
    select() if args.action=='select' else release()
