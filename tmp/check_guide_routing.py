"""Development-only route evaluation; labels never reach the router."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import json
from pathlib import Path
import re
import sys
import time

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from config import load_settings
from api_client import RagApiClient
from retrieval import route_guides,index,question_stem
from eval_dataset import contains_expected_concepts,normalize_text

parser=argparse.ArgumentParser()
parser.add_argument('--version',default='current')
args=parser.parse_args()
rows=[json.loads(line) for line in (root/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
rows=[r for r in rows if r['expected']['decision']=='answer' and len(r['expected']['answer'])>1]
guides={doc['id']:doc for doc in index()[0] if doc['id'].startswith('guide-')}
out=root/'output'/('route_audit_'+args.version+'.jsonl')

def evaluate(row):
    question=row['input']['text']
    client=RagApiClient(load_settings())
    routed=route_guides(question,client)
    identifiers=[str(file.get('metadata',{}).get('source_id','')).casefold() for file in routed]
    language='zh' if re.search(r'[\u4e00-\u9fff]',question_stem(question)) else 'en'
    text='\n'.join(guides[key]['text_'+language] for key in identifiers if key in guides)
    good,method,score=contains_expected_concepts(normalize_text(text),row['expected'].get('concepts'),.5)
    return {'id':row['id'],'question':question,'selected':identifiers,'coverage':good,'method':method,'score':score}

done=0;bad=0;start=time.monotonic()
with out.open('w',encoding='utf-8') as stream,ThreadPoolExecutor(max_workers=5) as pool:
    tasks=[pool.submit(evaluate,row) for row in rows]
    for task in as_completed(tasks):
        value=task.result();done+=1;bad+=not value['coverage']
        stream.write(json.dumps(value,ensure_ascii=False)+'\n');stream.flush()
        if not value['coverage']:print(json.dumps(value,ensure_ascii=False),flush=True)
        if done%25==0:print('Progress',done,'/',len(rows),'insufficient',bad,flush=True)
print('Finished',done,'insufficient',bad,'seconds',round(time.monotonic()-start,1),flush=True)
