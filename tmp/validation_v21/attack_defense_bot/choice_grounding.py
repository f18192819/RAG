"""Conservative source alignment for positively phrased implementation items.

No evaluation labels are used. Only an explicit known control, a validated
quotation of its bundled source, and a large mechanism-overlap margin can
correct a model choice. Ambiguous, negative and weak matches stay with the LLM.
"""
import json
import math
import re
import unicodedata
try:
    from .retrieval import index,terms,question_stem,strong_lexical_guide,local_search
    from .question_format import OPTION
except ImportError:
    from retrieval import index,terms,question_stem,strong_lexical_guide,local_search
    from question_format import OPTION


def align_choice_to_source(question: str,response: str,context: str,files) -> str:
    stem=question_stem(question)
    if not re.search(r'部署|实施|推进|做法|实践|implement|deploy|practice',stem,re.I):return response
    if re.search(r'错误|不正确|不符合|不属于|不合理|不恰当|不合适|不适合|不建议|不应|不推荐|误区|除外|例外|最不|最差|无效|\b(?:not|except|least|incorrect|inappropriate|unsuitable|worst|false|wrong)\b',stem,re.I):return response
    candidate=json.loads(response)
    if candidate.get('decision')!='answer':return response
    explicit=strong_lexical_guide(question)
    if not explicit:return response
    identifier=str(explicit[0]['metadata']['source_id']).casefold()
    documents,_,frequencies,_=index()
    guide=next((doc for doc in documents if doc['id']==identifier),None)
    if not guide:return response
    evidence=json.loads(context or '{}').get('validated_evidence',[])
    normalized=lambda value:' '.join(unicodedata.normalize('NFKC',value).split())
    quotes=[];citation=None
    for item in evidence:
        number=item.get('source')
        if type(number) is not int or not 1<=number<=len(files):continue
        source=files[number-1]
        quote=item.get('quote','')
        if str(source.get('metadata',{}).get('source_id','')).casefold()==identifier and len(quote)>=8 and normalized(quote) in normalized(guide['text']):
            quotes.append(quote);citation=number
    if not quotes:return response
    vocabulary=set(terms('\n'.join(quotes)))
    value=unicodedata.normalize('NFKC',question)
    matches=list(OPTION.finditer(value))
    if len(matches)!=4 or {m.group(1).upper() for m in matches}!=set('ABCD'):return response
    scores=[];mapped=[]
    for i,match in enumerate(matches):
        text=value[match.end():matches[i+1].start() if i+1<len(matches) else len(value)]
        shared=set(terms(text))&vocabulary
        weights=[math.log(1+(len(documents)-frequencies[word]+.5)/(frequencies[word]+.5)) for word in shared]
        scores.append((sum(weights),sum(weight>=2 for weight in weights),match.group(1).upper(),text))
        references=[hit for hit in local_search(text,30) if str(hit.get('metadata',{}).get('source_id','')).startswith('GUIDE-')]
        if len(references)>=2:
            first,second=references[:2]
            if str(first['metadata']['source_id']).casefold()==identifier and first['score']>=12 and first['score']>=1.4*second['score']:
                mapped.append((match.group(1).upper(),text))
    # An action can overlap several related controls. Classify its mechanisms
    # against the whole source catalog, not just against the requested guide.
    # Exactly one strongly supported option must map back to that guide.
    if len(mapped)==1 and not re.search(r'不需|无需|不要|不应|不做|不启|取消|绕过|跳过|禁用|\b(?:not|never|disable|skip)\b',mapped[0][1],re.I):
        winner=mapped[0][0]
        if winner!=candidate.get('answer','').strip().upper():
            candidate['answer']=winner
            candidate['evidence']=[citation]
            candidate['explanation']='依据已验证资料，选项 '+winner+' 的实施机制对应题干指定的控制。'
            return json.dumps(candidate,ensure_ascii=False)
    scores.sort(reverse=True)
    best,second=scores[:2]
    if best[0]<12 or best[1]<3 or best[0]<3*max(1,second[0]):return response
    if re.search(r'不需|无需|不要|不应|不做|不启|取消|绕过|跳过|禁用|\b(?:not|never|disable|skip)\b',best[3],re.I):return response
    if best[2]==candidate.get('answer','').strip().upper():return response
    candidate['answer']=best[2]
    candidate['evidence']=[citation]
    candidate['explanation']='依据已验证资料，选项 '+best[2]+' 覆盖该控制的关键实施机制。'
    return json.dumps(candidate,ensure_ascii=False)
