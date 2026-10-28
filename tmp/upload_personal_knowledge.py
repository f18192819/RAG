"""Idempotently publish the source-based control guides to the student's own DB."""
import json
from pathlib import Path
import sys
import argparse

ROOT=Path(__file__).resolve().parents[1]
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
sys.path.insert(0,str(PACKAGE))
from config import load_settings
from api_client import RagApiClient

def main():
    client=RagApiClient(load_settings())
    parser=argparse.ArgumentParser()
    parser.add_argument('--suffix',default='security_guides_v4')
    suffix=parser.parse_args().suffix
    names=client._get('/databases').get('databases',[])
    names=[n if isinstance(n,str) else n.get('database_name','') for n in names]
    existing=next((name for name in names if name.endswith('_'+suffix)),None)
    name=existing or client.create_database(suffix)
    records=[]
    for path in sorted((PACKAGE/'knowledge').glob('*guides.json')):
        records.extend(json.loads(path.read_text(encoding='utf-8'))['documents'])
    present=client.list_files(name,limit=1000)
    known={str(row.get('metadata',{}).get('source_id')) for row in present}
    files=[{'file':row['title']+'\n'+row['aliases']+'\n'+
                   ('RETRIEVAL DESCRIPTION (not source facts): '+row['retrieval_context']+'\n' if row.get('retrieval_context') else '')+row['text'],
            'metadata':{'source_id':row['id'],'source':row['source'],'title':row['title'],
                        'version':'2026-10-28-'+suffix,'kind':'source_based_knowledge_guide'}}
           for row in records if row['id'] not in known]
    if files:client.upload_files(name,files)
    env=PACKAGE/'.env'
    lines=[line for line in env.read_text(encoding='utf-8').splitlines() if not line.startswith('RAG_PERSONAL_DATABASE=')]
    lines.append('RAG_PERSONAL_DATABASE='+name)
    env.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({'database':name,'existing_documents':len(present),'new_documents':len(files)},ensure_ascii=False))

if __name__=='__main__':main()
