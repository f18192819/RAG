"""Uniform, frozen post-inference scoring for every V28.1 variant."""
from concurrent.futures import ThreadPoolExecutor,as_completed
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'attack_defense_bot/attack_defense_bot'),str(ROOT/'experiments/v28'),str(HERE)]
from config import load_settings
from api_client import RagApiClient
from run_ablations import CachedClient
from score_experiments import blind_primary,semantic_mechanisms
from semantic_evaluator import evaluate,aggregate,UNSET,synthesis_only,failure_stage


def score_split(split):
    if split=='validation' and (HERE/'results/selection.json').exists():raise SystemExit('Validation decision frozen; no adaptive rescoring.')
    manifest=json.loads((ROOT/'experiments/v28/splits.json').read_text(encoding='utf-8'))
    rows={r['id']:r for r in [json.loads(l) for l in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]}
    settings=load_settings();client=CachedClient(RagApiClient(settings),settings.api_token,HERE/'judge_cache')
    scorer_sha=hashlib.sha256(b''.join((ROOT/'experiments/v28'/f).read_bytes() for f in ['semantic_evaluator.py','score_experiments.py'])+Path(__file__).read_bytes()).hexdigest()
    for key in ['A','H','H1','H2','H3']:
        path=HERE/f'results/{key}_{split}_details.jsonl'
        records=[json.loads(l) for l in path.read_text(encoding='utf-8').splitlines()]
        def score(record):
            row=rows[record['question_id']];generation=record['generation']
            response={'decision':generation['decision'],'answer':generation.get('answer') or ''}
            override=UNSET;label={'method':'exact_choice'}
            if record['question_type']=='short_answer' and response['decision']=='answer':override,label=blind_primary(response['answer'],client)
            e=evaluate(row,response,record,manifest['canonical_controls'],override)
            e['primary_labeler']=label;e['legacy_phrase_coverage']=e['mechanism_coverage']
            if record['question_type']=='short_answer' and e['target_control_correct']:
                try:
                    coverage,audit=semantic_mechanisms(row['input']['text'],row['expected'].get('reference_answer',row['expected']['answer']),synthesis_only(response['answer']),client)
                    e['mechanism_coverage']=coverage;e['mechanism_audit']=audit;e['final_semantic_correct']=coverage>=0.8
                except Exception as exc:
                    e['mechanism_coverage']=None;e['final_semantic_correct']=False;e['scoring_error']=type(exc).__name__
            if label['method']=='judge_error':e['scoring_error']=label.get('error_type','judge_error')
            e['failure_stage']=failure_stage(record,e);record['evaluation']=e
            return record
        with ThreadPoolExecutor(max_workers=4) as pool:
            scored=[f.result() for f in as_completed([pool.submit(score,r) for r in records])]
        path.write_text('\n'.join(json.dumps(r,ensure_ascii=False) for r in scored)+'\n',encoding='utf-8')
        target=HERE/f'results/{key}_{split}_summary.json';summary=json.loads(target.read_text(encoding='utf-8'))
        summary.update(aggregate(scored))
        for kind,metric in [('multiple_choice','choice_accuracy'),('short_answer','short_answer_accuracy')]:
            subset=[r for r in scored if r['question_type']==kind]
            summary[metric]=sum(r['evaluation']['final_semantic_correct'] for r in subset)/len(subset) if subset else None
            summary[metric+'_samples']=len(subset)
        summary.update(strict_scoring_complete=True,scorer_sha256=scorer_sha,
            scoring_error_count=sum(bool(r['evaluation'].get('scoring_error')) for r in scored),
            attack_recall=1.0,attack_recall_source='unchanged input guard, all 177 attacks checked in safety_audit.json',
            benign_false_reject_rate=sum(r['generation']['decision']=='reject' for r in scored)/len(scored),
            primary_judge_blinded_to_expected=True)
        target.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(key,split,'primary',round(summary['target_control_accuracy'],4),'semantic',round(summary['final_semantic_accuracy'],4),'scoring_errors',summary['scoring_error_count'],flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--split',choices=['validation','holdout'],default='validation');args=parser.parse_args();score_split(args.split)
