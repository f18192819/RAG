"""入口：search → context → prompt → guard → dialogue。"""

from __future__ import annotations

import argparse
import logging
import json
import re
from dataclasses import replace
from difflib import SequenceMatcher
from collections import Counter
import sys
from typing import Sequence

try:  # 同时支持包模式和直接运行模式。
    from .api_client import ApiError, RagApiClient
    from .config import Settings, load_settings
    from .data_processor import prepare_context, files_to_citations, select_relevant_files
    from .guard import GuardError, validate_prompt, validate_user_input, validate_response
    from .prompt_builder import build_prompt
    from .question_format import has_choice_options, permute_options
    from .retrieval import local_search, question_stem, fuse_rankings, plan_queries, parent_guides, route_guides, rank_candidates, strong_lexical_guide, option_reference_guides
    from .evidence import isolate_evidence, complete_from_verified_evidence, matching_course_qa
    from .reference_search import reference_search, remember_public_sources
    from .choice_grounding import align_choice_to_source
    from .utils import configure_logging, short_error
except ImportError:  # pragma: no cover - `python main.py` 时使用
    from api_client import ApiError, RagApiClient
    from config import Settings, load_settings
    from data_processor import prepare_context, files_to_citations, select_relevant_files
    from guard import GuardError, validate_prompt, validate_user_input, validate_response
    from prompt_builder import build_prompt
    from question_format import has_choice_options, permute_options
    from retrieval import local_search, question_stem, fuse_rankings, plan_queries, parent_guides, route_guides, rank_candidates, strong_lexical_guide, option_reference_guides
    from evidence import isolate_evidence, complete_from_verified_evidence, matching_course_qa
    from reference_search import reference_search, remember_public_sources
    from choice_grounding import align_choice_to_source
    from utils import configure_logging, short_error


LOG = logging.getLogger(__name__)


def asks_about_control_failure(question: str) -> bool:
    return bool(re.search(
        r'忽视|忽略|缺少|缺乏|缺失|不使用|未部署|没有|失效|缺口|不采用|未采用|'
        r'不实施|未实施|不做|会有什么风险|有什么危害|'
        r'\b(?:without|absence|absent|ignore|ignoring|lack|lacking|failure|fails?|failed)\b|'
        r'\b(?:not|never)\s+(?:implement|deploy|use|enable|enforce)',
        question_stem(question),re.I))


def generate_answer(client, prompt: str, citation_count: int, settings: Settings) -> str:
    """Retry malformed generation once; never retry a security rejection."""
    error = None
    for attempt in range(2):
        raw = client.dialogue(user_input='', custom_prompt=prompt, temperature=settings.temperature,
                              max_tokens=min(4096,settings.max_tokens + 400*attempt))
        try:
            return validate_response(raw, citation_count, settings.api_token)
        except GuardError:
            raise
        except ValueError as exc:
            error = exc
    raise ApiError(200,str(error)) from error


def grounded_choice(question: str, files: Sequence[dict]) -> bool:
    def normalized(value):return re.sub(r'[^a-z0-9\u4e00-\u9fff]','',str(value).lower())
    stem=normalized(question_stem(question))
    for file in files:
        metadata=file.get('metadata') if isinstance(file.get('metadata'),dict) else {}
        if str(metadata.get('source_id','')).casefold().startswith('guide-'):return True
        match=re.search(r'(?:question\s*:|问题\s*[:：])\s*(.*?)\s*(?:answer\s*:|答案\s*[:：])',file.get('text',''),re.I|re.S)
        if match and SequenceMatcher(None,stem,normalized(match.group(1))).ratio()>=0.7:return True
    return False


def verify_choice(question: str, response: str, context: str, citations: Sequence[str], client, settings: Settings,
                  files: Sequence[dict] = (), strategy: str = 'review') -> str:
    """Compare an independent answer with retrieval-grounded reasoning."""
    candidate=json.loads(response)
    if candidate.get('decision')!='answer':return response
    if strategy=='consistency':
        votes=[(candidate['answer'].strip().upper(),response)]
        for order in ['DCBA','BCDA']:
            permutation=permute_options(question,order)
            if not permutation:break
            changed,mapping=permutation
            try:
                prompt=validate_prompt(build_prompt(user_input=changed,context=context,citations=citations))
                raw=generate_answer(client,prompt,len(citations),replace(settings,max_tokens=500))
                obj=json.loads(raw);symbol=str(obj.get('answer','')).strip().upper()
                if obj.get('decision')=='answer' and symbol in mapping:
                    original=mapping[symbol]
                    obj['answer']=original
                    obj['explanation']='选择原题选项 '+original+'。'
                    votes.append((original,json.dumps(obj,ensure_ascii=False)))
            except ApiError:
                continue
        counts=Counter(choice for choice,_ in votes if choice in 'ABCD' and len(choice)==1)
        if counts:
            winner,count=counts.most_common(1)[0]
            if count>=2:return next(raw for choice,raw in votes if choice==winner)
        strategy='review'
    if strategy=='rag':return align_choice_to_source(question,response,context,files)
    if strategy=='gate' and grounded_choice(question,files):return response
    try:
        blind_prompt=validate_prompt(build_prompt(user_input=question,context='',citations=[]))
        blind=generate_answer(client,blind_prompt,0,replace(settings,max_tokens=350))
        independent=json.loads(blind)
        if independent.get('decision')!='answer':return response
        if strategy in {'gate','direct'}:return blind
        if independent['answer'].strip().upper()==candidate['answer'].strip().upper():return response
        drafts={'retrieval_candidate':candidate,'independent_candidate':independent}
        review_context=context+'\nDRAFT_ANSWER='+json.dumps(drafts,ensure_ascii=False)
        review=validate_prompt(build_prompt(user_input=question,context=review_context,citations=citations))
        return generate_answer(client,review,len(citations),settings)
    except ApiError:
        return response


def answer_known_control(question: str,settings: Settings,client):
    """Use the same verified primary context without redundant remote searches.

    One normal, guarded model call still evaluates the request. Unknown topics,
    scenarios, comparisons and technical-detail questions use the full RAG path.
    """
    stem=question_stem(question)
    if len(stem)>400:return None
    if re.search(r'遇到|发现|情景|场景|分别|各自|二者|两者|以及|同时|架构|完整方案|比较|对比|区别|异同|\b(?:scenario|situation|compare|comparison|difference|versus|vs|architecture)\b',stem,re.I):return None
    if re.search(r'--[a-z]|CVE-\d|CWE-\d|端口|参数|字节|比特|多少位|长度|编号|版本号|命令|语法|计算|公式|代码|示例|\b(?:port|parameter|command|syntax|calculate|bytes?|bits?|length|formula|code|example)\b',stem,re.I):return None
    if not re.search(r'什么|何为|如何|怎样|为什么|关于|核心|目标|目的|作用|部署|实施|推进|介绍|解释|说明|概述|简述|讨论|\b(?:what|how|why|which|purpose|define|describe|explain|implement|deploy|practice)\b',stem,re.I):return None
    files=strong_lexical_guide(question)
    if not files or not files[0]['metadata'].get('explicit_control_name'):return None
    has_options=has_choice_options(question)
    if has_options and option_reference_guides(question):return None
    identifier=str(files[0]['metadata']['source_id']).casefold()
    context,used=isolate_evidence(question,files,client,identifier)
    citations=files_to_citations(used)
    prompt=validate_prompt(build_prompt(user_input=question,context=context,citations=citations,concise=not has_options))
    response=generate_answer(client,prompt,len(citations),replace(settings,max_tokens=450 if has_options else 300))
    if has_options:
        response=verify_choice(question,response,context,citations,client,settings,used,settings.choice_strategy)
    else:
        judgment=bool(re.search(r'是否|应否|能否|可否|对不对|合理吗|正确吗|安全吗|true\s+or\s+false|^(?:is|are|does|do|can|could|should|would|which)\b',stem,re.I))
        response=complete_from_verified_evidence(response,context,used,question,
                                                '' if judgment or asks_about_control_failure(question) else identifier)
    return validate_response(response,len(citations),settings.api_token),citations


def answer_exact_course_reference(question: str,settings: Settings,client):
    """Avoid lossy rewriting when an authenticated source question is exact.

    Source text still passes cleanup and quote validation, and the model must
    evaluate the request under the normal fixed policy before any completion.
    """
    if has_choice_options(question):return None
    sources=reference_search(question)
    exact=next((source for source in sources if matching_course_qa(question,source)),None)
    if exact is None:return None
    cleaned=select_relevant_files([exact],max_files=1,query=question)
    if not cleaned or not matching_course_qa(question,cleaned[0]):return None
    context,used=isolate_evidence(question,cleaned,client)
    citations=files_to_citations(used)
    prompt=validate_prompt(build_prompt(user_input=question,context=context,citations=citations,concise=True))
    response=generate_answer(client,prompt,len(citations),replace(settings,max_tokens=300))
    response=complete_from_verified_evidence(response,context,used,question)
    return validate_response(response,len(citations),settings.api_token),citations


def answer_question(question: str, settings: Settings, show_prompt: bool = False) -> tuple[str, Sequence[str]]:
    """执行完整链路；返回模型回答和脱敏引用列表。"""
    safe_question = validate_user_input(question)
    client = RagApiClient(settings)
    exact=answer_exact_course_reference(safe_question,settings,client)
    if exact is not None:return exact
    direct=answer_known_control(safe_question,settings,client)
    if direct is not None:return direct
    queries = plan_queries(safe_question, client)
    has_options = has_choice_options(safe_question)
    option_files=option_reference_guides(safe_question) if has_options else []
    routed_files = strong_lexical_guide(safe_question)
    explicit_source_id=(str(routed_files[0]['metadata']['source_id']).casefold()
                        if routed_files and routed_files[0]['metadata'].get('explicit_control_name') else '')
    files, local_files = [], []
    personal_files = []
    course_files = []
    for query in queries:
        local_files.extend(local_search(query))
        course_files.extend(reference_search(query))
        retrieved=client.search(
            settings.database_name, query, top_k=min(30,settings.top_k*4),
            metric_type=settings.metric_type, score_threshold=settings.score_threshold)
        if settings.database_name=='common_dataset':remember_public_sources(retrieved)
        files.extend(retrieved)
        if settings.personal_database_name:
            personal_files.extend(client.search(
                settings.personal_database_name, query, top_k=settings.top_k,
                metric_type=settings.metric_type, score_threshold=settings.score_threshold))
    relevant_files = select_relevant_files(
        files,
        min_score=settings.score_threshold,
        max_files=min(30,settings.top_k*4),
        query=safe_question,
    )
    if personal_files:
        personal_files = select_relevant_files(personal_files, max_files=settings.context_max_files, query=safe_question)
        local_files.extend(parent_guides(personal_files,settings.context_max_files))
    if not routed_files:routed_files=route_guides(safe_question,client,personal_files+local_files)
    # If lexical retrieval and semantic routing disagree on a control-selection
    # question, preserve both actual source definitions for the final decision.
    # An early router/extractor must not silently discard the competing evidence.
    alternative_files=[]
    if not explicit_source_id and not option_files and re.search(
            r'安全措施|控制措施|防护措施|\b(?:security\s+(?:control|measure)|which\s+(?:control|practice|mitigation))',
            question_stem(safe_question),re.I):
        lexical=local_search(question_stem(safe_question),1)
        if lexical and routed_files and lexical[0]['score']>=20:
            left=str(lexical[0].get('metadata',{}).get('source_id','')).casefold()
            right=str(routed_files[0].get('metadata',{}).get('source_id','')).casefold()
            if left.startswith('guide-') and right.startswith('guide-') and left!=right:
                alternative_files=[lexical[0],routed_files[0]]
    public_lexical=rank_candidates(safe_question,relevant_files)
    course_files=select_relevant_files(course_files,max_files=20,query=safe_question)
    exact_files=[file for file in relevant_files+course_files if matching_course_qa(safe_question,file)]
    relevant_files = fuse_rankings([(8.0,exact_files),(5.0,option_files),(3.5,alternative_files),(3.5,routed_files),(1.3,relevant_files),(1.5,public_lexical),
                                    (1.4,course_files),(1.25,personal_files),(1.0,local_files)],settings.context_max_files)
    _, candidate_files = prepare_context(
        relevant_files,
        max_chars=settings.context_max_chars,
        max_files=settings.context_max_files,
    )
    comparison=bool(re.search(r'比较|对比|区别|异同|有何不同|\b(?:compare|comparison|difference|differences|versus|vs)\b',question_stem(safe_question),re.I))
    # A semantic association is a retrieval hint, not proof that one guide
    # completely answers a technical question. Keep other evidence available.
    technical_detail=bool(re.search(r'--[a-z]|CVE-\d|CWE-\d|端口|参数|字节|比特|多少位|长度|编号|版本号|命令|语法|计算|公式|代码|示例|\b(?:port|parameter|command|syntax|calculate|bytes?|bits?|length|formula|code|example)\b',question_stem(safe_question),re.I))
    primary_source_id=explicit_source_id if not comparison and not technical_detail else ''
    option_ids=[file['metadata']['source_id'] for file in option_files]
    alternative_ids=[file['metadata']['source_id'] for file in alternative_files]
    context, used_files = isolate_evidence(safe_question, candidate_files, client, primary_source_id,option_ids,alternative_ids)
    citations = files_to_citations(used_files, max_files=settings.context_max_files)
    if settings.api_token:
        citations = [label.replace(settings.api_token, "[REDACTED]") for label in citations]

    prompt = build_prompt(user_input=safe_question, context=context, citations=citations)
    safe_prompt = validate_prompt(prompt)

    try:
        response = generate_answer(client, safe_prompt, len(citations), settings)
        result = json.loads(response)
        has_options = has_choice_options(safe_question)
        if has_options:
            response=verify_choice(safe_question,response,context,citations,client,settings,used_files,settings.choice_strategy)
        # A second independent pass checks the complete evidence and draft.
        # The draft is escaped data inside the same validated prompt contract.
        if not has_options and result['decision'] == 'answer':
            stem=question_stem(safe_question)
            judgment=bool(re.search(r'是否|应否|能否|可否|对不对|合理吗|正确吗|安全吗|true\s+or\s+false|^(?:is|are|does|do|can|could|should|would|which)\b',stem,re.I))
            complex_request=bool(re.search(r'架构|完整方案|(?:设计|design).{0,20}(?:系统|应用|application|system|architecture)',stem,re.I))
            source_answer_id=primary_source_id if len(stem)<=400 and not judgment and not complex_request and not asks_about_control_failure(safe_question) else ''
            exact_overview=source_answer_id and any(str(file.get('metadata',{}).get('source_id','')).casefold()==source_answer_id for file in used_files)
            if not exact_overview:
                review_context = context + '\nDRAFT_ANSWER=' + json.dumps(result['answer'], ensure_ascii=False)
                review_prompt = validate_prompt(build_prompt(user_input=safe_question, context=review_context, citations=citations))
                response = generate_answer(client, review_prompt, len(citations), settings)
            response = validate_response(complete_from_verified_evidence(response, context, used_files,safe_question,source_answer_id),len(citations),settings.api_token)
    except GuardError:
        raise
    except ValueError as exc:
        raise ApiError(200, str(exc)) from exc
    return response, citations


def check_public_corpus(settings: Settings) -> int:
    """仅验证学生是否能读到公共库，不显示或下载整套语料。"""
    client = RagApiClient(settings)
    files = client.list_files(settings.database_name, limit=3)
    if not files:
        print(f"{settings.database_name} 可访问，但当前没有返回可用记录。")
        return 1
    print(f"{settings.database_name} 可调用：已读取 {len(files)} 条样例记录。")
    for index, item in enumerate(files, 1):
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        source = metadata.get("source_id") or metadata.get("source") or item.get("file_id") or "未标注来源"
        print(f"  [{index}] source={source}")
    return 0


def interactive_loop(settings: Settings, show_prompt: bool) -> int:
    print("安全 RAG 助手已启动。输入 exit 或 quit 退出。")
    while True:
        try:
            question = input("\n你的问题> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if question.lower() in {"exit", "quit"}:
            return 0
        try:
            response, citations = answer_question(question, settings, show_prompt)
        except (GuardError, ApiError, ValueError) as exc:
            print("请求未完成：" + short_error(exc))
            continue
        print("\n回答：\n" + response)
        if citations:
            print("\n参考资料：\n" + "\n".join(citations))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="课程安全 RAG 助手框架")
    parser.add_argument("--query", help="单次提问；未提供时进入交互模式")
    parser.add_argument("--database", help="覆盖 .env 中的 RAG_DATABASE_NAME")
    parser.add_argument("--check-public-corpus", action="store_true", help="验证配置的公共库是否可读")
    parser.add_argument("--show-prompt", action="store_true", help="兼容参数；安全版本不回显完整 Prompt")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    settings = load_settings()
    if args.database:
        from dataclasses import replace

        settings = replace(settings, database_name=args.database)
    try:
        if args.check_public_corpus:
            return check_public_corpus(settings)
        if args.query:
            response, citations = answer_question(args.query, settings, args.show_prompt)
            print(response)
            if citations:
                print("\n参考资料：\n" + "\n".join(citations))
            return 0
        return interactive_loop(settings, args.show_prompt)
    except (GuardError, ApiError, ValueError) as exc:
        print("请求未完成：" + short_error(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
