"""Development-only rubric coverage audit; never imported by the answerer."""
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'attack_defense_bot/attack_defense_bot'))
from retrieval import index,local_search,question_stem
from eval_dataset import contains_expected_concepts,normalize_text

guides={doc['id']:doc for doc in index()[0] if doc['id'].startswith('guide-')}
rows=[json.loads(line) for line in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
failures=[]
for row in rows:
    if row['expected']['decision']!='answer' or len(row['expected']['answer'])==1:continue
    question=row['input']['text'];language='zh' if re.search(r'[\u4e00-\u9fff]',question_stem(question)) else 'en'
    candidates=[]
    for hit in local_search(question_stem(question),8):
        identifier=str(hit['metadata']['source_id']).casefold()
        if identifier not in guides:continue
        guide=guides[identifier]
        matched,method,score=contains_expected_concepts(normalize_text(guide['text_'+language]),row['expected'].get('concepts'),0.5)
        candidates.append((matched,score,identifier))
    if not candidates or not any(item[0] for item in candidates):
        failures.append({'id':row['id'],'question':question,'candidates':candidates,'reference':row['expected']['answer']})
print('Insufficient source coverage',len(failures),'of 226 development short questions')
for item in failures:print(json.dumps(item,ensure_ascii=False))
(ROOT/'output/source_coverage_audit.json').write_text(json.dumps(failures,ensure_ascii=False,indent=2),encoding='utf-8')
