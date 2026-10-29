"""Uniform post-inference scoring; blind taxonomy labels never see gold answers."""
from concurrent.futures import ThreadPoolExecutor,as_completed
import argparse
import hashlib
import json
from pathlib import Path
import sys
import unicodedata
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'attack_defense_bot/attack_defense_bot'),str(HERE)]
from config import load_settings
from api_client import RagApiClient
from retrieval import local_search,index
from semantic_evaluator import evaluate,aggregate,predicted_primary,synthesis_only,UNSET,failure_stage
from run_ablations import CachedClient


def normalized(value):return ' '.join(unicodedata.normalize('NFKC',str(value)).split())


def semantic_mechanisms(question,reference,answer,client):
    """Offline reference-to-answer entailment, after primary-control correctness.

    The rubric sees no model answer and is cached identically across variants.
    Every supported judgment must point to an actual answer span. These calls
    are evaluation only and never feed inference or the knowledge corpus.
    """
    policy='''Extract 1 to 3 essential atomic requirements from the supplied reference,
according to what the question asks. A purpose question may have one goal claim;
an implementation question needs its core mechanisms. Copy continuous reference
spans, not generic control names or trivial words. Do not add requirements.
Return exactly {"claims":["exact reference span"]}.
REFERENCE_JSON='''
    raw=client.dialogue(user_input='',custom_prompt=policy+json.dumps({'question':question,'reference':reference},ensure_ascii=False),temperature=0,max_tokens=450)
    value=json.loads(raw.strip().removeprefix('```json').removesuffix('```').strip())
    claims=value.get('claims')
    if set(value)!={'claims'} or not isinstance(claims,list) or not 1<=len(claims)<=3:raise ValueError('rubric_schema')
    if any(not isinstance(claim,str) or len(claim)<4 or normalized(claim) not in normalized(reference) for claim in claims):raise ValueError('rubric_source')
    policy='''Assess ONLY whether each supplied reference requirement is supported by
the actual answer. Accept semantic paraphrases, not merely shared keywords.
Do not repair or supplement the answer. Return every claim index exactly once:
{"support":[{"claim_index":0,"supported":true,"answer_quote":"exact continuous answer span"}]}.
For false support use an empty answer_quote. No extra keys.
ASSESSMENT_JSON='''
    raw=client.dialogue(user_input='',custom_prompt=policy+json.dumps({'claims':claims,'answer':answer},ensure_ascii=False),temperature=0,max_tokens=500)
    value=json.loads(raw.strip().removeprefix('```json').removesuffix('```').strip())
    support=value.get('support')
    if set(value)!={'support'} or not isinstance(support,list) or len(support)!=len(claims):raise ValueError('support_schema')
    seen=set()
    for row in support:
        if set(row)!={'claim_index','supported','answer_quote'} or type(row['claim_index']) is not int or row['claim_index'] not in range(len(claims)) or row['claim_index'] in seen or type(row['supported']) is not bool:raise ValueError('support_value')
        seen.add(row['claim_index'])
        if row['supported'] and (not isinstance(row['answer_quote'],str) or len(row['answer_quote'])<3 or normalized(row['answer_quote']) not in normalized(answer)):raise ValueError('support_span')
    return sum(row['supported'] for row in support)/len(claims),{'reference_claims':claims,'support':support}


def blind_primary(answer,client):
    answer=synthesis_only(answer)
    literal=predicted_primary(answer)
    if literal:return literal,{'method':'literal_primary','claim_quote':None}
    guides={doc['id']:doc for doc in index()[0] if doc['id'].startswith('guide-')}
    identifiers=[]
    for hit in local_search(answer,24):
        key=hit.get('metadata',{}).get('source_id','').casefold()
        if key in guides and key not in identifiers:identifiers.append(key)
        if len(identifiers)==12:break
    if not identifiers:return None,{'method':'unresolved','claim_quote':None}
    catalog=[{'id':key,'title':guides[key]['title'],'definition':guides[key]['text_en'][:500]} for key in identifiers]
    policy='''Map the PRIMARY recommendation actually expressed in ANSWER to a supplied control ID.
Do not solve an underlying question or repair the answer. No question or expected
answer is supplied. Later supplementary controls are not the primary claim.
An unambiguous mechanism can identify a control; shared generic security words cannot.
If the primary recommendation is unclear or ambiguous, return null.
Return exactly {"primary_control":"provided ID or null","claim_quote":"exact primary-claim span or empty"}.
DATA_JSON='''
    try:
        raw=client.dialogue(user_input='',custom_prompt=policy+json.dumps({'answer':answer,'catalog':catalog},ensure_ascii=False),temperature=0,max_tokens=160)
        value=json.loads(raw.strip().removeprefix('```json').removesuffix('```').strip())
        if set(value)!={'primary_control','claim_quote'}:raise ValueError('schema')
        key=value['primary_control'];quote=value['claim_quote']
        if key is None:return None,{'method':'blind_judge_unresolved','claim_quote':quote}
        if key not in identifiers or not isinstance(quote,str) or not quote or quote not in answer or answer.index(quote)>220:raise ValueError('unsupported_claim')
        return key,{'method':'blind_taxonomy_judge','claim_quote':quote}
    except Exception as exc:return None,{'method':'judge_error','error_type':type(exc).__name__,'claim_quote':None}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--split',choices=['validation','holdout'],default='validation');args=parser.parse_args()
    if args.split=='validation' and (HERE/'results/selection.json').exists():raise SystemExit('Validation selection is frozen; no adaptive rescoring.')
    manifest=json.loads((HERE/'splits.json').read_text(encoding='utf-8'))
    rows={row['id']:row for row in [json.loads(line) for line in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]}
    settings=load_settings();client=CachedClient(RagApiClient(settings),settings.api_token,HERE/'judge_cache')
    for path in sorted((HERE/'results').glob('*_'+args.split+'_details.jsonl')):
        records=[json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        def score(record):
            row=rows[record['question_id']];generation=record.get('generation',{})
            response={'decision':generation.get('decision','error'),'answer':generation.get('answer') or ''}
            override=UNSET;label={'method':'exact_choice'}
            if record['question_type']=='short_answer' and response['decision']=='answer':override,label=blind_primary(response['answer'],client)
            record['evaluation']=evaluate(row,response,record,manifest['canonical_controls'],override)
            record['evaluation']['primary_labeler']=label
            evaluation=record['evaluation']
            evaluation['legacy_phrase_coverage']=evaluation['mechanism_coverage']
            if record['question_type']=='short_answer' and evaluation['target_control_correct']:
                try:
                    coverage,audit=semantic_mechanisms(row['input']['text'],row['expected'].get('reference_answer',row['expected']['answer']),synthesis_only(response['answer']),client)
                    evaluation['mechanism_coverage']=coverage;evaluation['mechanism_audit']=audit
                    evaluation['final_semantic_correct']=coverage>=0.8
                except Exception as exc:
                    evaluation['mechanism_coverage']=None;evaluation['final_semantic_correct']=False
                    evaluation['scoring_error']=type(exc).__name__
            if label['method']=='judge_error':evaluation['scoring_error']=label.get('error_type','judge_error')
            evaluation['failure_stage']=failure_stage(record,evaluation)
            return record
        scored=[]
        with ThreadPoolExecutor(max_workers=4) as pool:
            for future in as_completed([pool.submit(score,record) for record in records]):scored.append(future.result())
        path.write_text('\n'.join(json.dumps(record,ensure_ascii=False) for record in scored)+'\n',encoding='utf-8')
        summary_path=path.with_name(path.name.replace('_details.jsonl','_summary.json'))
        previous=json.loads(summary_path.read_text(encoding='utf-8'))
        previous.update(aggregate(scored));previous['strict_scoring_complete']=True
        previous['scoring_error_count']=sum(bool(row['evaluation'].get('scoring_error')) for row in scored)
        previous['scorer_sha256']=hashlib.sha256((HERE/'semantic_evaluator.py').read_bytes()+(HERE/'score_experiments.py').read_bytes()).hexdigest()
        previous['primary_judge_blinded_to_expected']=True
        summary_path.write_text(json.dumps(previous,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(path.stem,previous['target_control_accuracy'],previous['final_semantic_accuracy'],flush=True)

if __name__=='__main__':main()
