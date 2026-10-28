"""Test previously observed topic mistakes; expectations remain development-only."""
import json
from pathlib import Path
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from main import answer_question
from config import load_settings
rows=json.loads((root/'output/v26_semantic_topic_audit.json').read_text(encoding='utf-8'))
# The source development group conflates encryption-key and application-secret
# terminology in these two questions; do not force either interpretation.
rows=[row for row in rows if row['id'] not in {'public-normal-train-syn-0211','public-normal-train-syn-0213'}]
settings=load_settings()
target=root/'output/v26_semantic_regression.jsonl'

def run(row):
    started=time.monotonic()
    try:
        response,citations=answer_question(row['question'],settings)
        obj=json.loads(response)
        return {'id':row['id'],'question':row['question'],
                'desired_source':row['desired_source'],'response':obj,'citations':citations,
                'correct_source_retained':obj.get('decision')=='answer' and any(row['desired_source'].casefold() in value.casefold() for value in citations),
                'seconds':round(time.monotonic()-started,2)}
    except Exception as exc:
        return {'id':row['id'],'error':type(exc).__name__,'correct_source_retained':False}

with target.open('w',encoding='utf-8') as stream,ThreadPoolExecutor(max_workers=4) as pool:
    for task in as_completed([pool.submit(run,row) for row in rows]):
        result=task.result()
        stream.write(json.dumps(result,ensure_ascii=False)+'\n');stream.flush()
        print(json.dumps({**result,'response':str(result.get('response'))[:500]},ensure_ascii=False),flush=True)
