"""Bounded source-only signals for conditional review, never answer labels."""
import json
import re
import unicodedata


def _terms(text):
    text=unicodedata.normalize('NFKC',text).casefold()
    words=set(re.findall(r'[a-z][a-z0-9_-]{2,}',text))
    stop={'the','and','for','with','that','from','are','its','this','into','through','must','should','security','control','data'}
    words-=stop
    for run in re.findall(r'[\u4e00-\u9fff]+',text):
        words.update(run[i:i+2] for i in range(len(run)-1))
    return words


def review_reasons(answer, context, conflict=False):
    """Only flag visibly terse/low-coverage drafts backed by substantive quotes.

    Lexical overlap is a review trigger, never a correctness score. The review
    model must compare meanings, retain an adequate draft and avoid padding.
    """
    if conflict:return ['source_control_conflict']
    quotes=[item['quote'] for item in json.loads(context or '{}').get('validated_evidence',[])]
    substantial=[q for q in quotes if len(q)>=100]
    if not substantial:return []
    clauses=[s.strip() for q in substantial for s in re.split(r'(?<=[。.!?;；])\s*',q) if len(_terms(s))>=5]
    if len(clauses)<2:return []
    answer_terms=_terms(answer)
    covered=sum(len(answer_terms & _terms(clause))/max(1,len(_terms(clause)))>=0.25 for clause in clauses)
    source_length=max(map(len,substantial))
    terse=len(answer)<source_length*0.65
    if terse and covered<len(clauses)*0.6:return ['source_mechanism_coverage_low']
    return []
