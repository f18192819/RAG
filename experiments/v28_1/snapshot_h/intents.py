"""Generic question intent, independent of any development question templates."""
import re
try:
    from .question_format import choice_stem,has_choice_options
except ImportError:
    from question_format import choice_stem,has_choice_options


def is_control_overview_question(question,identifier=None):
    if has_choice_options(question):return False
    stem=choice_stem(question)
    excluded=r'如果|忽视|缺少|缺失|没有|不使用|未使用|不部署|后果|缺口|危害|比较|对比|区别|场景|遇到|发生|--?[a-zA-Z]|CVE-\d|CWE-\d|端口|参数(?!化)|代码|命令|计算|是否|能否|应否|\b(?:without|absence|lack|ignore|compare|difference|scenario|happen|parameter|command|calculate|should|can|could|does|is\s+it)\b'
    if len(stem)>220 or re.search(excluded,stem,re.I):return False
    overview=bool(re.search(r'什么是|何为|核心.{0,6}(?:目标|目的|作用)|的(?:定义|目标|目的|作用)|如何(?:实施|部署)|(?:介绍|解释|概述|简述)|\b(?:define|definition|overview|purpose|core\s+goal|what\s+is|how\s+to\s+implement)\b',stem,re.I))
    if not overview or identifier is None:return overview
    try:from .query_planning import control_names
    except ImportError:from query_planning import control_names
    names=next((names for key,names in control_names() if key==identifier),[])
    remainder=stem.casefold()
    for name in sorted(names,key=len,reverse=True):
        pattern=re.escape(name.casefold()).replace(r'\-',r'[-\s]').replace(r'\ ',r'[\s-]+')
        remainder=re.sub(pattern,' ',remainder)
    remainder=re.sub(r'请|介绍|解释|概述|简述|什么|何为|核心|安全|目标|目的|作用|如何|实施|部署|定义|的|是',' ',remainder)
    words=re.findall(r'[a-z]+|[\u4e00-\u9fff]+',remainder)
    return bool(names) and all(word in {'what','is','the','primary','security','purpose','of','define','definition','overview','core','goal','how','to','implement','deploy','explain','describe','please','a','an'} for word in words)


def is_specific_technical_question(question):
    return bool(re.search(r'CVE-\d|CWE-\d|--[a-zA-Z]|端口|参数(?!化)|字节|位数|命令|语法|计算|\b(?:port|parameter|command|syntax|bytes?|calculate)\b',choice_stem(question),re.I))
