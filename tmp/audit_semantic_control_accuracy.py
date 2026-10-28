"""Development-only topic audit, independent of the permissive 50% concept score.

Group metadata is used only to compare results after generation; it never
enters runtime code, prompts, sources or uploaded knowledge.
"""
import collections
import json
from pathlib import Path
import re
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from retrieval import strong_lexical_guide

dataset=[json.loads(line) for line in (root/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
by_id={row['id']:row for row in dataset}
groups=collections.defaultdict(collections.Counter)
for row in dataset:
    if row['expected']['decision']!='answer':continue
    hits=strong_lexical_guide(row['input']['text'])
    if hits and hits[0]['metadata'].get('explicit_control_name'):
        groups[row['provenance']['augmentation_group']][hits[0]['metadata']['source_id'].casefold()]+=1
expected={group:counter.most_common(1)[0][0] for group,counter in groups.items()}
details=next((root/'output/v22_all_short_online').glob('*details.jsonl'))
misses=[]
for line in details.read_text(encoding='utf-8').splitlines():
    result=json.loads(line)
    original=by_id[result['id']]
    desired=expected.get(original['provenance']['augmentation_group'])
    cited=[identifier.casefold() for citation in result['citations']
           for identifier in re.findall(r'GUIDE-[A-Za-z0-9-]+',citation)]
    if desired and (not cited or desired not in cited):
        misses.append({'id':result['id'],'question':result['input_text'],'desired_source':desired,
                       'cited_sources':cited,'answer':result['actual_answer'],
                       'permissive_score':result['answer_match_score']})
print('Mapped groups:',len(expected),'topic absent from citations:',len(misses))
for row in misses:
    print(json.dumps({**row,'answer':row['answer'][:180]},ensure_ascii=False))
(root/'output/v26_semantic_topic_audit.json').write_text(json.dumps(misses,ensure_ascii=False,indent=2),encoding='utf-8')
