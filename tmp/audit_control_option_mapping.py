"""Development-only check of source-control classification of action options."""
import json
from pathlib import Path
import re
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from retrieval import local_search,strong_lexical_guide,question_stem
from question_format import OPTION
rows=[json.loads(line) for line in (root/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
count=bad=0
for row in rows:
 q=row['input']['text'];stem=question_stem(q)
 if row['expected']['decision']!='answer' or len(row['expected']['answer'])!=1:continue
 if not re.search(r'部署|实施|推进|做法|实践|implement|deploy|practice',stem,re.I):continue
 if re.search(r'错误|不正确|不符合|不属于|误区|除外|例外|最不|\b(?:not|except|least)\b',stem,re.I):continue
 primary=strong_lexical_guide(q)
 if not primary:continue
 identifier=primary[0]['metadata']['source_id']
 matches=list(OPTION.finditer(q));supported=[];details=[]
 for i,match in enumerate(matches):
  text=q[match.end():matches[i+1].start() if i+1<len(matches) else len(q)]
  hits=[h for h in local_search(text,30) if h['metadata']['source_id'].startswith('GUIDE-')]
  if len(hits)<2:continue
  best,second=hits[:2]
  detail=(match.group(1).upper(),best['metadata']['source_id'],round(best['score'],2),round(second['score'],2))
  details.append(detail)
  if best['metadata']['source_id']==identifier and best['score']>=12 and best['score']>=1.4*second['score'] and not re.search(r'不需|无需|不要|不应|不做|不启|取消|绕过|跳过|禁用|\b(?:not|never|disable|skip)\b',text,re.I):supported.append(match.group(1).upper())
 if len(supported)!=1:continue
 count+=1
 if supported[0]!=row['expected']['answer']:
  bad+=1;print(json.dumps({'q':q,'primary':identifier,'options':details,'prediction':supported[0],'expected':row['expected']['answer']},ensure_ascii=False))
print('Control-mechanism mapping',count,'predictions;',bad,'incorrect')
