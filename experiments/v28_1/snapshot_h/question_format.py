"""One format parser shared by the guard, retrieval and generation stages."""
import re
import unicodedata

OPTION=re.compile(r'(?i)(?:^|(?<=[\s;；]))[\(\[]?\s*([a-d])\s*[).。、:：\]]\s*')


def strip_question_header(text: str) -> str:
    value=unicodedata.normalize('NFKC',text).strip()
    header=r'^(?:【(?:问题|题目|简答题|单选题|判断题)】|\[(?:question|problem)\]|(?:问题|题目|question|problem|q)\s*[:：])\s*'
    for _ in range(3):
        changed=re.sub(header,'',value,count=1,flags=re.I)
        if changed==value:break
        value=changed.strip()
    return value

def has_choice_options(text: str) -> bool:
    value=unicodedata.normalize('NFKC',text)
    return {'a','b'}.issubset({match.group(1).casefold() for match in OPTION.finditer(value)})

def choice_stem(text: str) -> str:
    value=unicodedata.normalize('NFKC',text)
    if not has_choice_options(value):return strip_question_header(value)
    marker=value.find('【选项】')
    if marker>=0:return strip_question_header(value[:marker])
    first=next((match for match in OPTION.finditer(value) if match.group(1).casefold()=='a'),None)
    return strip_question_header(value[:first.start()]) if first else strip_question_header(value)


def is_chinese_question(text: str) -> bool:
    value=choice_stem(text)
    if re.search(r'用中文|中文作答|中文回答|(?:answer|respond|reply)\s+in\s+chinese',value,re.I):return True
    if re.search(r'用英文|英文作答|英文回答|(?:answer|respond|reply)\s+in\s+english',value,re.I):return False
    if re.match(r'^(?:what|why|how|which|when|where|explain|describe|define|discuss|list|true|false|is|are|does|do|can|could|should|would|compare)\b',value,re.I):return False
    if re.search(r'为什么|是什么|如何|怎样|是否|应否|什么|的核心|哪项|哪个',value):return True
    chinese=len(re.findall(r'[\u4e00-\u9fff]',value))
    english=len(re.findall(r'[A-Za-z]{2,}',value))
    return chinese>0 and (english<5 or chinese>english*2)

def permute_options(text: str, order: str):
    value=unicodedata.normalize('NFKC',text)
    matches=list(OPTION.finditer(value))
    if len(matches)!=4 or {m.group(1).upper() for m in matches}!=set('ABCD') or set(order)!=set('ABCD'):
        return None
    choices={}
    for i,match in enumerate(matches):
        end=matches[i+1].start() if i+1<len(matches) else len(value)
        choices[match.group(1).upper()]=value[match.end():end].strip()
    if not all(choices.values()):return None
    mapping=dict(zip('ABCD',order))
    question=choice_stem(value)+'\n【选项】\n'+'\n'.join(label+'. '+choices[old] for label,old in mapping.items())
    return question,mapping
