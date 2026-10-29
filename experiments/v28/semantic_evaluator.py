"""Strict offline evaluation. Expected labels never reach inference code."""
from __future__ import annotations
from collections import Counter
import re
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
sys.path.insert(0,str(PACKAGE))
from control_routing import primary_control_mention
from question_format import OPTION

GENERIC={'数据','访问','风险','验证','保护','权限','监测','安全','控制','管理','要求','机制',
         'data','access','risk','security','control','management','protection','verification'}


def synthesis_only(answer):
    return re.split(r'\n\n(?:实施依据|课程参考原文|Supporting control guidance|Course reference excerpt)',str(answer or ''),maxsplit=1)[0]


def predicted_primary(answer):
    # Critically, supplementary paragraphs cannot turn a wrong first claim right.
    return primary_control_mention(synthesis_only(answer))


def strict_mechanism_coverage(answer,concepts,reference=''):
    text=synthesis_only(answer).casefold()
    groups=[]
    for group in concepts or []:
        phrases=[str(term).strip().casefold() for term in group if isinstance(term,str)]
        phrases=[term for term in phrases if term not in GENERIC and
                 (len(re.findall(r'[\u4e00-\u9fff]',term))>=4 or len(term.split())>=2 or
                  re.fullmatch(r'[a-z0-9]{2,12}',term) and term.upper() in {'MFA','DLP','TLS','CSRF','XSS','PAM','SSO','DNS','NDR','EDR','KMS','HSM','RTO','RPO','SBOM','SAST','DAST'})]
        if phrases and (not reference or any(phrase in reference.casefold() for phrase in phrases)):groups.append(phrases)
    if not groups:return None
    return sum(any(phrase in text for phrase in group) for group in groups)/len(groups)


UNSET=object()


def evaluate(row,response,trace,canonical,primary_override=UNSET):
    desired=canonical.get(row.get('provenance',{}).get('augmentation_group',''))
    expected=row['expected'];decision=response.get('decision','error')
    choice=expected.get('answer') in {'A','B','C','D'}
    answer=response.get('answer') or ''
    predicted=predicted_primary(answer) if not choice else None
    if not choice and primary_override is not UNSET:predicted=primary_override
    choice_correct=choice and decision=='answer' and answer.strip().upper()==expected['answer']
    if choice:
        # The selected letter is the primary claim for an MC question. Gold is
        # consumed only here, after inference; wrong options are classified blind.
        if choice_correct:predicted=desired
        else:
            matches=list(OPTION.finditer(row['input']['text']))
            for i,match in enumerate(matches):
                if match.group(1).upper()==answer.strip().upper():
                    end=matches[i+1].start() if i+1<len(matches) else len(row['input']['text'])
                    predicted=predicted_primary(row['input']['text'][match.end():end])
    control_correct=bool(choice_correct) if choice else bool(desired and predicted==desired and decision=='answer')
    coverage=strict_mechanism_coverage(answer,expected.get('concepts'),expected.get('reference_answer',expected.get('answer',''))) if control_correct and not choice else None
    # Primary correctness is necessary; a mere 50% shared-keyword match is never sufficient.
    semantic_correct=choice_correct if choice else control_correct and (coverage is None or coverage>=0.8)
    candidates=trace.get('retrieval',{}).get('candidate_sources',[])
    rankings=trace.get('router',{}).get('ranking',[])
    ranked=[item['source_id'] for item in rankings] or trace.get('fusion',{}).get('sources',[])
    position=ranked.index(desired)+1 if desired in ranked else None
    retained=trace.get('evidence',{}).get('retained_sources',[])
    stage='none'
    if desired and not semantic_correct:
        if desired not in candidates:stage='retrieval_miss'
        elif position!=1:stage='rerank_miss'
        elif desired not in retained:stage='evidence_drop'
        else:stage='generation_miss'
    return {'expected_control':desired,'predicted_control':predicted,'target_control_correct':control_correct,
            'answer_primary_control_correct':control_correct,'mechanism_coverage':coverage,
            'final_semantic_correct':bool(semantic_correct),'choice_correct':bool(choice_correct),
            'candidate_recall':{str(k):desired in candidates[:k] for k in [1,3,5]},
            'rerank_correct':position==1,'reciprocal_rank':1/position if position else 0.0,
            'evidence_survived':desired in retained,'correct_source_retrieved':desired in candidates,
            'source_survival':{stage:desired in trace.get(stage,{}).get(field,[]) for stage,field in
                [('retrieval','candidate_sources'),('fusion','sources'),('prepared','sources'),('evidence','retained_sources')]},
            'failure_stage':stage,'primary_unresolved':not bool(predicted)}


def aggregate(results):
    scored=[row['evaluation'] for row in results if row.get('evaluation',{}).get('expected_control')]
    def mean(key):return sum(float(row[key]) for row in scored)/len(scored) if scored else None
    retrieved=[row for row in scored if row['correct_source_retrieved']]
    modes=Counter(row.get('evidence',{}).get('mode','unknown') for row in results)
    fallback=[row['evaluation'] for row in results if row.get('evidence',{}).get('mode')=='fallback' and 'evaluation' in row]
    confusion=Counter((row['expected_control'],row['predicted_control'] or 'unresolved') for row in scored if not row['target_control_correct'] and row['predicted_control']!=row['expected_control'])
    return {'samples':len(results),'scored_control_samples':len(scored),
        'error_count':sum(bool(row.get('error_type')) for row in results),
        'target_control_accuracy':mean('target_control_correct'),'answer_primary_control_accuracy':mean('answer_primary_control_correct'),
        'candidate_recall':{str(k):sum(row['candidate_recall'][str(k)] for row in scored)/len(scored) if scored else None for k in [1,3,5]},
        'rerank_accuracy':mean('rerank_correct'),'MRR':mean('reciprocal_rank'),
        'evidence_survival':sum(row['evidence_survived'] for row in retrieved)/len(retrieved) if retrieved else None,
        'final_semantic_accuracy':mean('final_semantic_correct'),'primary_unresolved_rate':mean('primary_unresolved'),
        'fallback_accuracy':sum(row['final_semantic_correct'] for row in fallback)/len(fallback) if fallback else None,
        'evidence_modes':dict(modes),'failure_stages':dict(Counter(row['failure_stage'] for row in scored)),
        'top_confusions':[{'desired':a,'predicted':b,'count':count} for (a,b),count in confusion.most_common()]}
