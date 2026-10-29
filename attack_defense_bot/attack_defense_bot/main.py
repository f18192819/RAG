"""Independent retrieval, bounded scope contrast, verified evidence and synthesis."""
from __future__ import annotations
import argparse
import json
import logging
import sys
from typing import Sequence
try:
    from .api_client import ApiError,RagApiClient
    from .config import Settings,load_settings,RRF_WEIGHTS
    from .data_processor import prepare_context,files_to_citations,select_relevant_files
    from .guard import GuardError,validate_prompt,validate_user_input,validate_response
    from .prompt_builder import build_prompt,build_complete_prompt
    from .answer_review import review_reasons
    from .question_format import has_choice_options
    from .retrieval import local_search,question_stem,fuse_rankings,parent_guides,rank_candidates,strong_lexical_guide,option_reference_guides
    from .query_planning import plan_query_representation,QueryPlan
    from .control_routing import route_candidate_guides,contrastive_rerank_guides,primary_control_mention
    from .evidence import isolate_evidence,complete_from_verified_evidence,matching_course_qa
    from .reference_search import reference_search,remember_public_sources
    from .diagnostics import record,source_ids
    from .intents import is_control_overview_question,is_specific_technical_question
    from .utils import configure_logging,short_error
except ImportError:
    from api_client import ApiError,RagApiClient
    from config import Settings,load_settings,RRF_WEIGHTS
    from data_processor import prepare_context,files_to_citations,select_relevant_files
    from guard import GuardError,validate_prompt,validate_user_input,validate_response
    from prompt_builder import build_prompt,build_complete_prompt
    from answer_review import review_reasons
    from question_format import has_choice_options
    from retrieval import local_search,question_stem,fuse_rankings,parent_guides,rank_candidates,strong_lexical_guide,option_reference_guides
    from query_planning import plan_query_representation,QueryPlan
    from control_routing import route_candidate_guides,contrastive_rerank_guides,primary_control_mention
    from evidence import isolate_evidence,complete_from_verified_evidence,matching_course_qa
    from reference_search import reference_search,remember_public_sources
    from diagnostics import record,source_ids
    from intents import is_control_overview_question,is_specific_technical_question
    from utils import configure_logging,short_error

LOG=logging.getLogger(__name__)


def generate_answer(client,prompt,citation_count,settings):
    error=None
    for attempt in range(2):
        raw=client.dialogue(user_input='',custom_prompt=prompt,temperature=settings.temperature,max_tokens=min(4096,settings.max_tokens+400*attempt))
        try:return validate_response(raw,citation_count,settings.api_token)
        except GuardError:raise
        except ValueError as exc:error=exc
    raise ApiError(200,str(error)) from error


def _answer_with_evidence(question,context,used,client,settings,source_answer_id=''):
    citations=files_to_citations(used,max_files=settings.context_max_files)
    if settings.api_token:citations=[item.replace(settings.api_token,'[REDACTED]') for item in citations]
    complete=settings.answer_completeness and not has_choice_options(question) and bool(used)
    builder=build_complete_prompt if complete else build_prompt
    prompt=validate_prompt(builder(user_input=question,context=context,citations=citations))
    response=generate_answer(client,prompt,len(citations),settings)
    value=json.loads(response)
    primary=primary_control_mention(value.get('answer') or '') if value['decision']=='answer' and not has_choice_options(question) else None
    actual_guides=[identifier for identifier in source_ids(used) if identifier.startswith('guide-')]
    conflict=bool(primary and actual_guides and primary not in actual_guides)
    reasons=review_reasons(value.get('answer') or '',context,conflict) if complete and value['decision']=='answer' else ['source_control_conflict'] if conflict else []
    attempted=bool(reasons and not source_answer_id)
    review_error=None
    if attempted:
        if complete:
            revised=json.loads(context);revised['DRAFT_ANSWER']=value;revised['review_trigger']=reasons
            revised_context=json.dumps(revised,ensure_ascii=False)
        else:revised_context=context+'\nDRAFT_ANSWER='+json.dumps(value,ensure_ascii=False)
        corrected=validate_prompt(builder(user_input=question,context=revised_context,citations=citations))
        try:response=generate_answer(client,corrected,len(citations),settings)
        except GuardError:raise
        except (ApiError,ValueError) as exc:
            # A failed optional review must not discard an already valid draft.
            review_error=type(exc).__name__
    response=complete_from_verified_evidence(response,context,used,question,source_answer_id=source_answer_id)
    response=validate_response(response,len(citations),settings.api_token)
    value=json.loads(response)
    record('generation',primary_control=primary_control_mention(value.get('answer') or ''),
           answer=value.get('answer'),decision=value['decision'],correction_attempted=attempted,review_reasons=reasons,review_error=review_error)
    return response,citations


def answer_known_control(question,settings,client):
    if not is_control_overview_question(question):return None
    files=strong_lexical_guide(question)
    if not files or not files[0]['metadata'].get('explicit_control_name'):return None
    identifier=source_ids(files)[0]
    if not is_control_overview_question(question,identifier):return None
    _,files=prepare_context(files,max_chars=settings.context_max_chars,max_files=1)
    record('retrieval',queries=[question_stem(question)],candidate_sources=source_ids(files))
    record('router',candidate_controls=source_ids(files),ranking=[{'source_id':identifier,'score':1.0,'reason_code':'object_match'}],top1_margin=1.0,explicit_named=True)
    record('fusion',sources=source_ids(files));record('prepared',sources=source_ids(files))
    context,used=isolate_evidence(question,files,client,primary_source_id=identifier)
    return _answer_with_evidence(question,context,used,client,settings,source_answer_id=identifier)


def answer_exact_course_reference(question,settings,client):
    if has_choice_options(question):return None
    exact=next((item for item in reference_search(question) if matching_course_qa(question,item)),None)
    if exact is None:return None
    cleaned=select_relevant_files([exact],max_files=1,query=question)
    if not cleaned or not matching_course_qa(question,cleaned[0]):return None
    record('retrieval',queries=[question_stem(question)],candidate_sources=source_ids(cleaned))
    record('fusion',sources=source_ids(cleaned));record('prepared',sources=source_ids(cleaned))
    context,used=isolate_evidence(question,cleaned,client)
    return _answer_with_evidence(question,context,used,client,settings)


def answer_question(question,settings,show_prompt=False):
    safe=validate_user_input(question)
    if settings.production_profile=='A':
        try:from .baseline_v17.main import answer_question as baseline_answer
        except ImportError:from baseline_v17.main import answer_question as baseline_answer
        return baseline_answer(safe,settings,show_prompt)
    client=RagApiClient(settings)
    exact=answer_exact_course_reference(safe,settings,client)
    if exact is not None:return exact
    overview=answer_known_control(safe,settings,client)
    if overview is not None:return overview
    plan=plan_query_representation(safe,client) if settings.query_representation else QueryPlan([question_stem(safe)])
    choices=has_choice_options(safe)
    options=option_reference_guides(safe) if choices else []
    named=strong_lexical_guide(safe)
    named=[item for item in named if item.get('metadata',{}).get('explicit_control_name')]
    dense=[];local=[];course=[];personal=[]

    def retrieve(query):
        local.extend(local_search(query,12));course.extend(reference_search(query))
        fetched=client.search(settings.database_name,query,top_k=min(30,settings.top_k*4),metric_type=settings.metric_type,score_threshold=settings.score_threshold)
        if settings.database_name=='common_dataset':remember_public_sources(fetched)
        dense.extend(fetched)
        if settings.personal_database_name:
            personal.extend(client.search(settings.personal_database_name,query,top_k=settings.top_k,metric_type=settings.metric_type,score_threshold=settings.score_threshold))

    def pool():
        actual=select_relevant_files(dense,min_score=settings.score_threshold,max_files=30,query=safe)
        private=select_relevant_files(personal,max_files=12,query=safe)
        parents=parent_guides(private,12)
        lexical=rank_candidates(safe,actual)
        corpus=select_relevant_files(course,max_files=20,query=safe)
        independent=fuse_rankings([(RRF_WEIGHTS['dense'],actual),(RRF_WEIGHTS['public_bm25'],lexical),
            (RRF_WEIGHTS['course_bm25'],corpus),(RRF_WEIGHTS['personal'],parents),(RRF_WEIGHTS['local_bm25'],local)],20)
        return actual,private,parents,lexical,corpus,independent

    for query in plan.queries:retrieve(query)
    actual,private,parents,lexical,corpus,independent=pool()
    candidates=route_candidate_guides(safe,(independent if settings.candidate_retention else [])+parents+local)
    retained=[];ranking=[];uncertain=False
    technical=is_specific_technical_question(safe)
    if not choices and not technical and settings.contrastive_rerank:
        retained,ranking,_,uncertain=contrastive_rerank_guides(safe,plan.features,candidates,client,settings.rerank_margin,settings.rerank_min_score)
        supplemental=plan.supplemental_query() if uncertain and settings.supplemental_retrieval else None
        if supplemental:
            retrieve(supplemental);plan.queries.append(supplemental)
            actual,private,parents,lexical,corpus,independent=pool()
            updated=route_candidate_guides(safe,parents+local)
            if source_ids(updated)!=source_ids(candidates):
                candidates=updated
                retained,ranking,_,uncertain=contrastive_rerank_guides(safe,plan.features,candidates,client,settings.rerank_margin,settings.rerank_min_score)
            record('supplemental',performed=True,query=supplemental,count=1)
    else:
        record('router',candidate_controls=source_ids(candidates),ranking=[],top1_margin=None,not_applied='choice' if choices else 'technical' if technical else 'disabled')
    record('retrieval',queries=plan.queries,document_sources=source_ids(independent))
    exact_files=[item for item in actual+corpus if matching_course_qa(safe,item)]
    applicable=bool(ranking and ranking[0]['score']>=settings.rerank_min_score)
    hints=retained if applicable else []
    routes=[(RRF_WEIGHTS['exact'],exact_files),(RRF_WEIGHTS['options'],options),
        (RRF_WEIGHTS['explicit_named'],named),(RRF_WEIGHTS['contrastive'],hints),
        (RRF_WEIGHTS['dense'],actual),(RRF_WEIGHTS['public_bm25'],lexical),
        (RRF_WEIGHTS['course_bm25'],corpus),(RRF_WEIGHTS['personal'],parents),
        (RRF_WEIGHTS['local_bm25'],local)]
    if settings.candidate_retention:
        # Independent retrieval already performs weighted fusion. Consume its
        # actual ranking once, rather than recomputing or merely logging it.
        routes=routes[:4]+[(1.0,independent)]
    fused=fuse_rankings(routes,settings.context_max_files)
    preservation=[]
    if settings.candidate_retention and not choices and not technical and not exact_files:
        # These are competing hypotheses, not a unique answer. Reserve all
        # bounded candidates ahead of external hits; quote validation below
        # still requires their actual registered source text.
        preservation=retained if applicable else candidates
        fused=preserve_candidates(fused,preservation,settings.context_max_files)
    if uncertain and applicable and not options and not exact_files:
        # Preserve competing retrieved sources without making a control decision.
        mandatory=retained[:2]
        fused=mandatory+[item for item in fused if source_ids([item])[0] not in set(source_ids(mandatory))]
        fused=fused[:settings.context_max_files]
    record('fusion',sources=source_ids(fused),reserved_candidates=source_ids(preservation),independent_consumed=settings.candidate_retention)
    _,prepared=prepare_context(fused,max_chars=settings.context_max_chars,max_files=settings.context_max_files)
    record('prepared',sources=source_ids(prepared))
    selected=[identifier for identifier in source_ids(prepared) if identifier.startswith('guide-')] if choices or applicable or named or preservation else []
    context,used=isolate_evidence(safe,prepared,client,control_source_ids=source_ids(options),retained_source_ids=selected)
    return _answer_with_evidence(safe,context,used,client,settings)


def preserve_candidates(fused,candidates,limit):
    """Reserve bounded competing canonical sources without a semantic verdict."""
    seen=set();output=[]
    for item in list(candidates)[:3]+list(fused):
        key=source_ids([item])[0]
        if key in seen:continue
        seen.add(key);output.append(item)
    return output[:limit]


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
