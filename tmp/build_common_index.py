"""Read-only course-corpus mirror with a compact SQLite FTS5 BM25 index."""
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
sys.path.insert(0,str(PACKAGE))
from config import load_settings
from api_client import RagApiClient
from retrieval import terms

def main():
    client=RagApiClient(load_settings())
    target=PACKAGE/'knowledge/common_lexical.sqlite3'
    connection=sqlite3.connect(target)
    connection.execute('CREATE TABLE IF NOT EXISTS documents(file_id TEXT PRIMARY KEY,text TEXT,metadata TEXT)')
    connection.execute("CREATE VIRTUAL TABLE IF NOT EXISTS lexical USING fts5(tokens, file_id UNINDEXED)")
    offset=connection.execute('SELECT count(*) FROM documents').fetchone()[0]
    while True:
        body=client._get('/databases/common_dataset/files',{'offset':offset,'limit':500})
        rows=body.get('files',[])
        if not rows:break
        inserted=0
        for row in rows:
            identifier=str(row['file_id'])
            if connection.execute('SELECT 1 FROM documents WHERE file_id=?',(identifier,)).fetchone():continue
            text=str(row.get('text',''))
            metadata=json.dumps(row.get('metadata',{}),ensure_ascii=False)
            question=text.split('Answer:',1)[0]
            tokens=' '.join(terms(question)*2+terms(text))
            connection.execute('INSERT INTO documents VALUES(?,?,?)',(identifier,text,metadata))
            connection.execute('INSERT INTO lexical(tokens,file_id) VALUES(?,?)',(tokens,identifier))
            inserted+=1
        connection.commit()
        offset+=len(rows)
        print('Read-only indexed',offset,'records; new',inserted,flush=True)
        if len(rows)<500:break
    connection.execute("INSERT INTO lexical(lexical) VALUES('optimize')")
    connection.commit()
    print('Finished',target.stat().st_size,'bytes;',offset,'records',flush=True)
    connection.close()

if __name__=='__main__':main()
