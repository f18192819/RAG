"""Development-only evaluation of conservative source-to-choice alignment."""
import json
import math
from pathlib import Path
import re
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from retrieval import index,strong_lexical_guide,terms,question_stem
from question_format import OPTION
D,C,F,A=index();guides={d['id']:d for d in D if d['id'].startswith('guide-')}
rows=[json.loads(line) for line in (root/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
n=bad=0
for row in rows:
    q=row['input']['text'];stem=question_stem(q)
    if row['expected']['decision']!='answer' or len(row['expected']['answer'])!=1:continue
    if not re.search(r'部署|实施|推进|做法|实践|implement|deploy|practice',stem,re.I):continue
    if re.search(r'错误|不正确|不符合|不属于|误区|除外|例外|最不|\b(?:not|except|least)\b',stem,re.I):continue
    hits=strong_lexical_guide(q)
    if not hits:continue
    doc=guides.get(hits[0]['metadata']['source_id'].casefold())
    if not doc:continue
    lang='zh' if re.search(r'[\u4e00-\u9fff]',stem) else 'en'
    vocab=set(terms(doc['text_'+lang]));matches=list(OPTION.finditer(q));scores=[]
    for i,m in enumerate(matches):
        text=q[m.end():matches[i+1].start() if i+1<len(matches) else len(q)]
        shared=set(terms(text))&vocab
        weights=[math.log(1+(len(D)-F[w]+.5)/(F[w]+.5)) for w in shared]
        scores.append((sum(weights),sum(w>=2 for w in weights),m.group(1).upper(),text))
    scores.sort(reverse=True)
    if len(scores)<2:continue
    first,second=scores[:2]
    if first[0]<12 or first[1]<3 or first[0]<3*max(1,second[0]):continue
    if re.search(r'不需|无需|不要|不应|不做|不启|取消|绕过|跳过|禁用|\b(?:not|never|disable|skip)\b',first[3],re.I):continue
    n+=1
    if first[2]!=row['expected']['answer']:
        bad+=1;print(json.dumps({'q':q,'source':doc['id'],'scores':scores,'expected':row['expected']['answer']},ensure_ascii=False))
print('Conservative source alignment',n,'predictions;',bad,'incorrect')
