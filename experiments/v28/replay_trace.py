"""Recover pre-router candidate IDs from pinned deterministic legacy retrieval.

This replays no model call and changes no generated answer. It repairs the
diagnostic distinction between a control catalog and mixed raw QA document IDs.
Only question text and actually recorded queries enter retrieval.
"""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--variant',choices=list('ABCDE'),required=True)
    parser.add_argument('--split',choices=['validation','holdout'],default='validation');args=parser.parse_args()
    sys.path.insert(0,str(HERE/'baseline_v17'))
    from retrieval import local_search,question_stem,strong_lexical_guide,fuse_rankings
    from question_format import has_choice_options
    path=HERE/('results/'+args.variant+'_'+args.split+'_details.jsonl')
    records=[json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
    rows={row['id']:row for row in [json.loads(line) for line in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]}
    def ids(items):return [str(hit.get('metadata',{}).get('source_id',hit.get('file_id',''))).casefold() for hit in items]
    for record in records:
        question=rows[record['question_id']]['input']['text'];retrieval=record.setdefault('retrieval',{})
        if args.variant=='E' and record.get('router',{}).get('ranking'):
            # Its real Top3 scope-candidate generation already records its pool.
            continue
        local=[]
        for query in retrieval.get('queries',[]):local.extend(local_search(query))
        if not has_choice_options(question):
            strong=strong_lexical_guide(question) if args.variant in {'A','B'} else []
            if strong:candidates=ids(strong)
            else:
                candidates=[]
                for hit in local_search(question_stem(question),20)+local:
                    key=ids([hit])[0]
                    if key.startswith('guide-') and key not in candidates:candidates.append(key)
                candidates=candidates[:18]
        else:candidates=ids(fuse_rankings([(1.0,[hit for hit in local if ids([hit])[0].startswith('guide-')])],20))
        if 'document_sources' not in retrieval:retrieval['document_sources']=retrieval.get('candidate_sources',[])
        retrieval['candidate_sources']=candidates
        retrieval['diagnostic_replay']='pinned deterministic candidate stage; answers unchanged; no model calls'
    path.write_text('\n'.join(json.dumps(record,ensure_ascii=False) for record in records)+'\n',encoding='utf-8')
    print(args.variant,args.split,'candidate diagnostic replayed without model execution')

if __name__=='__main__':main()
