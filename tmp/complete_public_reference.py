"""Read-only public-corpus ingestion using documented numeric search filters.

The offset-based listing has a finite window. Numeric ID ranges read the same
authorized common_dataset records; no other database is queried or changed.
"""
import json
from pathlib import Path
import sqlite3
import sys

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from api_client import RagApiClient,ApiError
from config import load_settings
from retrieval import terms

client=RagApiClient(load_settings())
connection=sqlite3.connect(root/'tmp/common_lexical.sqlite3')
known={int(row[0]) for row in connection.execute('SELECT file_id FROM documents')}
start=min(known);cursor=max(known);added=0;batch=500;empty=0;complete=False

def save(rows):
    global added
    for row in rows:
        identifier=str(row['file_id'])
        if int(identifier) in known:continue
        text=str(row.get('text',''))
        metadata=json.dumps(row.get('metadata',{}),ensure_ascii=False)
        tokens=' '.join(terms(text.split('Answer:',1)[0])*2+terms(text))
        connection.execute('INSERT INTO documents VALUES(?,?,?)',(identifier,text,metadata))
        connection.execute('INSERT INTO lexical(tokens,file_id) VALUES(?,?)',(tokens,identifier))
        known.add(int(identifier));added+=1
    connection.commit()

# Resolve small holes in the already-read window without assuming they exist.
if cursor-start<100000:
    for identifier in sorted(set(range(start,cursor+1))-known):
        save(client.search('common_dataset','Question Answer cybersecurity',top_k=1,expr=f'file_id == {identifier}'))

while added<50000:
    upper=cursor+batch
    try:
        rows=client.search('common_dataset','Question Answer cybersecurity',top_k=batch,
                           expr=f'file_id > {cursor} and file_id <= {upper}')
    except ApiError as exc:
        if exc.status_code in {400,422} and batch>10:
            batch=max(10,batch//2);print('Adjusted public read batch',batch,flush=True);continue
        raise
    save(rows)
    cursor=upper
    if rows:
        empty=0
        print('Public source records',len(known),'new',added,flush=True)
    else:
        remaining=client.search('common_dataset','Question Answer cybersecurity',top_k=1,expr=f'file_id > {cursor}')
        if not remaining:complete=True;break
        empty+=1
        if empty>=10:
            print('Non-contiguous later ID range; retained sources without claiming completeness.',flush=True);break

earlier=client.search('common_dataset','Question Answer cybersecurity',top_k=1,expr=f'file_id < {start}')
complete=complete and not earlier
connection.execute("INSERT INTO lexical(lexical) VALUES('optimize')")
connection.commit();connection.close()
result={'records':len(known),'added':added,'complete_observed_public_id_range':complete,'database':'common_dataset','operations':'read_only'}
(root/'output/public_reference_ingestion.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result),flush=True)
