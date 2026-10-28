"""Lexical retrieval over a read-only snapshot of course source material.

Source QA documents come from common_dataset, not an evaluation dataset.
SQLite FTS5 indexes source questions and bodies separately. Source text is
always untrusted and still passes through evidence isolation and validation.
"""
from __future__ import annotations
import json
from collections import OrderedDict
from pathlib import Path
import re
import sqlite3
import threading
import unicodedata
from html import unescape

try:
    from .retrieval import terms, question_stem
except ImportError:
    from retrieval import terms, question_stem

_lock=threading.RLock()
_connection=None
_documents=[]
_source_documents={}
_public_sources=OrderedDict()


def _index():
    global _connection,_documents,_source_documents
    with _lock:
        if _connection is not None:return _connection
        path=Path(__file__).resolve().parent/'knowledge/course_reference.jsonl'
        if not path.exists():return None
        documents=[]
        database=sqlite3.connect(':memory:',check_same_thread=False)
        try:
            database.execute('CREATE VIRTUAL TABLE reference USING fts5(question,body,document UNINDEXED)')
            # JSON strings may contain U+2028/U+2029; splitlines() would split
            # a valid record inside its string. JSONL boundaries are LF only.
            for line in path.read_text(encoding='utf-8').split('\n'):
                if not line.strip():continue
                identifier,text=json.loads(line)
                question=re.split(r'\n(?:Answer|答案)\s*[:：]',text,maxsplit=1,flags=re.I)[0]
                database.execute('INSERT INTO reference VALUES(?,?,?)',
                                 (' '.join(terms(question)),' '.join(terms(text)),len(documents)))
                documents.append((identifier,text))
            database.commit()
        except (sqlite3.Error,ValueError,TypeError):
            database.close()
            return None
        _documents=documents
        _source_documents={str(identifier):text for identifier,text in documents}
        _connection=database
        return database


def is_course_reference_excerpt(identifier, text: str) -> bool:
    """Check against bundled or actually retrieved source, never metadata alone."""
    if not str(identifier).isdigit():return False
    with _lock:original=_public_sources.get(str(identifier),'')
    if not original:
        if _index() is None:return False
        original=_source_documents.get(str(identifier),'')
    def normalized(value):
        value=unicodedata.normalize('NFKC',unescape(value))
        value=''.join(char for char in value if unicodedata.category(char)!='Cf' and
                      (unicodedata.category(char)!='Cc' or char in '\n\r\t'))
        return ' '.join(value.split())
    excerpt=normalized(text)
    return len(excerpt)>=8 and bool(original) and excerpt in normalized(original)


def remember_public_sources(files) -> None:
    """Record actual authenticated common_dataset responses for provenance.

    Called by the application only after a public-database search, never from
    question/model data. Source contents remain untrusted; this establishes
    their origin and does not skip quote/schema/instruction validation.
    """
    with _lock:
        for source in files:
            identifier=str(source.get('file_id',''))
            text=source.get('text')
            if not identifier.isdigit() or not isinstance(text,str) or not text.strip():continue
            _public_sources[identifier]=text
            _public_sources.move_to_end(identifier)
        while len(_public_sources)>4096:_public_sources.popitem(last=False)


def reference_search(question: str, top_k: int = 12) -> list[dict]:
    database=_index()
    if database is None:return []
    words=list(dict.fromkeys(terms(question_stem(question))))[:48]
    if not words:return []
    match=' OR '.join('"'+word.replace('"','""')+'"' for word in words)
    with _lock:
        try:
            found=database.execute(
                'SELECT document,bm25(reference,3.0,1.0,0.0) FROM reference WHERE reference MATCH ? ORDER BY 2 LIMIT ?',
                (match,top_k)).fetchall()
        except sqlite3.Error:return []
    result=[]
    for rank,(number,score) in enumerate(found):
        identifier,text=_documents[int(number)]
        result.append({'file_id':str(identifier),'text':text,
                       'score':1/(1+rank*.05),
                       'metadata':{'source_id':'COURSE-REF-'+str(identifier),'source':'common_dataset'}})
    return result
