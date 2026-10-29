"""Real offline guard/lexical metrics, explicitly not an online ablation."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'attack_defense_bot/attack_defense_bot'))
from guard import validate_user_input,GuardError
from retrieval import local_search
from control_routing import route_candidate_guides


def main():
    manifest=json.loads((ROOT/'experiments/v28/splits.json').read_text(encoding='utf-8'))
    rows=[json.loads(line) for line in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
    counts=Counter()
    for row in rows:
        try:validate_user_input(row['input']['text']);rejected=False
        except GuardError:rejected=True
        desired=row['expected']['decision']=='reject'
        counts['tp' if rejected and desired else 'fp' if rejected else 'fn' if desired else 'tn']+=1
    result={'mode':'offline_guard_and_original_query_BM25_only','real_model_inference':False,
            'guard':dict(counts),'attack_recall':counts['tp']/(counts['tp']+counts['fn']),
            'benign_guard_false_reject_rate':counts['fp']/(counts['fp']+counts['tn']),
            'model_benign_false_reject_rate':None,'splits':{}}
    for split in ['validation','holdout']:
        ids=set(manifest['evaluation_subset'][split]);subset=[row for row in rows if row['id'] in ids]
        recall=Counter();route_recall=0
        for row in subset:
            expected=manifest['canonical_controls'][row['provenance']['augmentation_group']]
            hits=[hit.get('metadata',{}).get('source_id','').casefold() for hit in local_search(row['input']['text'],20)]
            candidates=[hit.get('metadata',{}).get('source_id','').casefold() for hit in route_candidate_guides(row['input']['text'])]
            for k in [1,3,5]:recall[k]+=expected in hits[:k]
            route_recall+=expected in candidates
        result['splits'][split]={'samples':len(subset),'BM25_recall':{str(k):recall[k]/len(subset) for k in [1,3,5]},
                                'bounded_candidate_recall_at_3':route_recall/len(subset),
                                'rerank_accuracy':None,'MRR':None,'final_semantic_accuracy':None}
    folder=ROOT/'experiments/v28/results';folder.mkdir(exist_ok=True)
    (folder/'offline_metrics.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
