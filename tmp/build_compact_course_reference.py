"""Export only the already-read, read-only common_dataset source documents.

No development evaluation questions, expected labels or rubrics are read.
This stores ordinary source text; the submission archive compresses it once.
"""
import json
from pathlib import Path
import sqlite3

root=Path(__file__).resolve().parents[1]
db=sqlite3.connect(root/'tmp/common_lexical.sqlite3')
target=root/'tmp/course_reference.jsonl'
with target.open('w',encoding='utf-8',newline='\n') as output:
    for identifier,text,raw_meta in db.execute('SELECT file_id,text,metadata FROM documents ORDER BY rowid'):
        row=[identifier,text]
        output.write(json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n')
print('Exported public course source documents:',target.stat().st_size,'bytes')
