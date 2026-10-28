"""Validate ordinary, authorized source QA; no evaluation labels are read."""
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from main import answer_question
from config import load_settings
from evidence import clean

identifiers=['459970008184525958','459970008184525959',
             '459970008184524901','459970008184525334']
database=sqlite3.connect(root/'tmp/common_lexical.sqlite3')
rows=[]
for identifier in identifiers:
    text=database.execute('SELECT text FROM documents WHERE file_id=?',(identifier,)).fetchone()[0]
    match=re.fullmatch(r'Question:\s*(.*?)\s+Answer:\s*(.+)',text,re.I|re.S)
    rows.append((identifier,*match.groups()))
settings=load_settings()

def run(row):
    identifier,question,reference=row
    started=time.monotonic()
    try:
        response,citations=answer_question(question,settings)
        value=json.loads(response)
        return {'source_id':identifier,'question':question,'reference':reference,
                'response':value,'citations':citations,'seconds':round(time.monotonic()-started,2),
                'source_retained':clean(reference) in clean(value.get('answer') or '')}
    except Exception as exc:
        return {'source_id':identifier,'question':question,'error':type(exc).__name__,
                'seconds':round(time.monotonic()-started,2)}

results=[]
with ThreadPoolExecutor(max_workers=4) as pool:
    for task in as_completed([pool.submit(run,row) for row in rows]):
        result=task.result(); results.append(result)
        print(json.dumps(result,ensure_ascii=False),flush=True)
(root/'output/v24_original_source_checks.json').write_text(
    json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
