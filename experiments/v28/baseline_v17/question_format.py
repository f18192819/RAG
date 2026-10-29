"""One format parser shared by the guard, retrieval and generation stages."""
import re
import unicodedata

OPTION=re.compile(r'(?i)(?:^|(?<=[\s;；]))[\(\[]?\s*([a-d])\s*[).。、:：\]]\s*')

def has_choice_options(text: str) -> bool:
    value=unicodedata.normalize('NFKC',text)
    return {'a','b'}.issubset({match.group(1).casefold() for match in OPTION.finditer(value)})

def choice_stem(text: str) -> str:
    value=unicodedata.normalize('NFKC',text)
    if not has_choice_options(value):return value
    marker=value.find('【选项】')
    if marker>=0:return value[:marker].strip()
    first=next((match for match in OPTION.finditer(value) if match.group(1).casefold()=='a'),None)
    return value[:first.start()].strip() if first else value

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
