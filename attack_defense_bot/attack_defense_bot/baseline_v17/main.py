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
    from .prompt_builder import build_prompt, build_template_prompt
    from .question_format import has_choice_options, permute_options
    from .retrieval import local_search, question_stem, fuse_rankings, plan_queries, parent_guides, route_guides, rank_candidates, strong_lexical_guide, index, guide_file
    from .evidence import isolate_evidence, complete_from_verified_evidence
    from .reference_search import reference_search
    from .answer_compiler import (
        build_deterministic_evidence_fallback,
        classify_short_answer_template,
        compile_response_json,
        knn_predict_control,
        knn_predict_mc,
        resolve_control_id,
        resolve_explicit_control_id,
    )
    from .utils import configure_logging, short_error
except ImportError:  # pragma: no cover - `python main.py` 时使用
    from api_client import ApiError, RagApiClient
    from config import Settings, load_settings
    from data_processor import prepare_context, files_to_citations, select_relevant_files
    from guard import GuardError, validate_prompt, validate_user_input, validate_response
    from prompt_builder import build_prompt, build_template_prompt
    from question_format import has_choice_options, permute_options
    from retrieval import local_search, question_stem, fuse_rankings, plan_queries, parent_guides, route_guides, rank_candidates, strong_lexical_guide, index, guide_file
    from evidence import isolate_evidence, complete_from_verified_evidence
    from reference_search import reference_search
    from answer_compiler import (
        build_deterministic_evidence_fallback,
        classify_short_answer_template,
        compile_response_json,
        knn_predict_control,
        knn_predict_mc,
        resolve_control_id,
        resolve_explicit_control_id,
    )
    from utils import configure_logging, short_error

try:
    from ..diagnostics import record as diag_record
except ImportError:
    try:
        from diagnostics import record as diag_record
    except ImportError:
        def diag_record(stage: str, **values) -> None:
            pass


LOG = logging.getLogger(__name__)
try:
    from ..security import guarded_request,checked_input,request_client,rejection_response
    from ..answer_review import review_reasons
    from ..control_routing import primary_control_mention
except ImportError:
    from security import guarded_request,checked_input,request_client,rejection_response
    from answer_review import review_reasons
    from control_routing import primary_control_mention


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
                    if sum(choice == original for choice, _ in votes) >= 2:
                        # A third vote cannot overturn an existing majority.
                        return next(raw for choice, raw in votes if choice == original)
            except ApiError:
                continue
        counts=Counter(choice for choice,_ in votes if choice in 'ABCD' and len(choice)==1)
        if counts:
            winner,count=counts.most_common(1)[0]
            if count>=2:return next(raw for choice,raw in votes if choice==winner)
        # Bound disagreement handling to two reordered answers. With no
        # majority, preserve the initial grounded answer instead of escalating
        # to additional blind/judge calls with the same model.
        return response
    if strategy=='rag' or (strategy=='gate' and grounded_choice(question,files)):return response
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


@guarded_request
def answer_question(question: str, settings: Settings, show_prompt: bool = False) -> tuple[str, Sequence[str]]:
    """执行完整链路；返回模型回答和脱敏引用列表。"""
    safe_question = checked_input(question)
    client = request_client(settings,RagApiClient)

    has_options = has_choice_options(safe_question)
    template_kind = classify_short_answer_template(safe_question)
    # All inferred controls (including new scenario phrasings) require a
    # mechanism check. Explicitly named control questions keep their fast path.
    scenario_reasoning = not has_options and template_kind in {'T3_scenario', 'generic'}
    guides = {doc['id']: doc for doc in index()[0] if doc['id'].startswith('guide-')}

    fast_path = bool(getattr(settings, 'fast_path_named_controls', False))
    use_hybrid_knn = bool(getattr(settings, 'hybrid_knn_router', False))
    use_knn_only = bool(getattr(settings, 'knn_only_router', False))
    allow_patches = not bool(getattr(settings, 'disable_handwritten_scenario_patches', False))
    committed_append = bool(getattr(settings, 'committed_guide_append', False))
    use_mc_knn_fallback = bool(getattr(settings, 'mc_knn_fallback', False))
    exclude_ids = set(getattr(settings, 'knn_exclude_ids', ()))

    query_rewrite_calls = 0
    routing_calls = 0
    evidence_extraction_calls = 0
    generation_calls = 0
    review_calls = 0
    route_method = 'none'
    knn_info = {}

    routed_files = []
    queries = []
    mc_primary_ids: list[str] = []

    if not has_options:
        # B2: Fast path for T1/T2/T4/T5 with explicit canonical control name in stem
        if fast_path and template_kind in {'T1_neglect', 'T2_implementation', 'T4_purpose_zh', 'T5_purpose_en'}:
            explicit_id = resolve_explicit_control_id(safe_question)
            if explicit_id and explicit_id in guides:
                queries = [question_stem(safe_question)]
                routed_files = [guide_file(guides[explicit_id])]
                route_method = 'fast_path_explicit'

        # B3 / R2 / R3: Hybrid kNN + LLM router for T3 / remaining short answers
        if not routed_files and (use_hybrid_knn or use_knn_only):
            knn_info = knn_predict_control(
                safe_question,
                min_top1_score=getattr(settings, 'knn_min_top1_score', 0.42),
                min_margin=getattr(settings, 'knn_min_margin', 0.10),
                exclude_ids=exclude_ids,
            )
            pred_id = str(knn_info.get('predicted_control') or '')
            if not scenario_reasoning and (use_knn_only or knn_info.get('high_confidence')) and pred_id in guides:
                queries = [question_stem(safe_question)]
                routed_files = [guide_file(guides[pred_id])]
                route_method = 'knn_only' if use_knn_only else 'knn_high_confidence'
    else:
        # Fast path for MC when explicit control or option controls are present
        if fast_path:
            stem_line = safe_question.splitlines()[0]
            sc = resolve_explicit_control_id(stem_line)
            if sc and sc in guides:
                mc_primary_ids.append(sc)
            else:
                opts = [m.group(2).strip() for m in re.finditer(r'(?m)^\s*([ABCD])[\.、:：\)]\s*(.+)$', safe_question)]
                if len(opts) == 4 and not any('通用控制描述' in o for o in opts):
                    for o in opts:
                        oc = resolve_explicit_control_id(o)
                        if oc and oc in guides and oc not in mc_primary_ids:
                            mc_primary_ids.append(oc)
                for h in local_search(safe_question, 5):
                    sid = str(h.get('metadata', {}).get('source_id', '')).casefold()
                    if sid in guides and sid not in mc_primary_ids:
                        mc_primary_ids.append(sid)
            if mc_primary_ids:
                queries = [question_stem(safe_question)]
                routed_files = [guide_file(guides[c]) for c in mc_primary_ids[:5]]
                route_method = 'mc_deterministic_guides'

    if not queries:
        queries = plan_queries(safe_question, client)
        query_rewrite_calls = 1

    files, local_files = [], []
    personal_files = []
    course_files = []
    for query in queries:
        local_files.extend(local_search(query))
        course_files.extend(reference_search(query))
        files.extend(client.search(
            settings.database_name, query, top_k=min(30,settings.top_k*4),
            metric_type=settings.metric_type, score_threshold=settings.score_threshold))
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

    if not has_options:
        if not routed_files:
            knn_cands = [knn_info.get('predicted_control', ''), knn_info.get('top2_control', '')] if knn_info else None
            if scenario_reasoning or not strong_lexical_guide(safe_question):
                routing_calls = 1
            routed_files = route_guides(safe_question, client, personal_files + local_files,
                                        knn_candidates=knn_cands, verify_scenario=scenario_reasoning)
            route_method = 'llm_fallback' if knn_info else 'llm_router'

        if not scenario_reasoning and (getattr(settings, 'anchor_canonical', False) or getattr(settings, 'verified_support_append', False) or committed_append):
            routed_id = str(routed_files[0]['metadata']['source_id']).casefold() if routed_files else ''
            resolved_id = resolve_control_id(
                safe_question, '', routed_files, routed_id, allow_scenario_patches=allow_patches
            )
            if resolved_id and resolved_id != routed_id and resolved_id in guides:
                routed_files = [guide_file(guides[resolved_id])]
                route_method = f"{route_method}+patch" if allow_patches else route_method

    public_lexical=rank_candidates(safe_question,relevant_files)
    course_files=select_relevant_files(course_files,max_files=20,query=safe_question)
    relevant_files = fuse_rankings([(3.5,routed_files),(1.3,relevant_files),(1.5,public_lexical),
                                    (1.4,course_files),(1.25,personal_files),(1.0,local_files)],settings.context_max_files)
    # A selected local source must survive fusion even if many dense hits agree.
    if routed_files:
        retained={f['metadata']['source_id'].casefold() for f in routed_files}
        relevant_files=(routed_files+[f for f in relevant_files
            if str(f.get('metadata',{}).get('source_id', '')).casefold() not in retained])[:settings.context_max_files]
    diag_record('fusion', sources=[str(f.get('metadata',{}).get('source_id', '')).casefold() for f in relevant_files])
    _, candidate_files = prepare_context(
        relevant_files,
        max_chars=settings.context_max_chars,
        max_files=settings.context_max_files,
    )
    diag_record('prepared', sources=[str(f.get('metadata',{}).get('source_id', '')).casefold() for f in candidate_files])
    if has_options:
        primary_source_id = ','.join(mc_primary_ids[:5]) if mc_primary_ids else ''
    else:
        primary_source_id = (str(routed_files[0]['metadata']['source_id']).casefold() if routed_files else '')

    if not primary_source_id and candidate_files:
        evidence_extraction_calls = 1
    context, used_files = isolate_evidence(safe_question, candidate_files, client, primary_source_id)
    diag_record('evidence', retained_sources=[str(f.get('metadata',{}).get('source_id', '')).casefold() for f in used_files])
    citations = files_to_citations(used_files, max_files=settings.context_max_files)
    if settings.api_token:
        citations = [label.replace(settings.api_token, "[REDACTED]") for label in citations]

    use_template = getattr(settings, 'template_prompt', False) and not has_options
    builder = build_template_prompt if use_template else build_prompt
    prompt = builder(user_input=safe_question, context=context, citations=citations)
    safe_prompt = validate_prompt(prompt)

    enable_compiler = bool(
        getattr(settings, 'neglect_completion', False)
        or getattr(settings, 'anchor_canonical', False)
        or getattr(settings, 'verified_support_append', False)
        or committed_append
    )
    fail_soft = bool(getattr(settings, 'fail_soft_handling', False))
    skip_review = bool(getattr(settings, 'skip_unconditional_review', False))

    diag_record(
        'router',
        route_method=route_method,
        primary_source_id=primary_source_id,
        knn_top1=knn_info.get('predicted_control', ''),
        knn_top1_score=knn_info.get('top1_score', 0.0),
        knn_margin=knn_info.get('margin', 0.0),
        knn_high_confidence=knn_info.get('high_confidence', False),
    )

    try:
        try:
            generation_calls += 1
            response = generate_answer(client, safe_prompt, len(citations), settings)
        except GuardError:
            raise
        except (ApiError, ValueError) as first_exc:
            if fail_soft and not has_options:
                fallback = build_deterministic_evidence_fallback(
                    safe_question,
                    context,
                    used_files,
                    primary_source_id,
                    len(citations),
                    allow_scenario_patches=allow_patches,
                    committed_guide_append=committed_append,
                )
                if fallback is not None:
                    diag_record(
                        'llm_calls',
                        query_rewrite_calls=query_rewrite_calls,
                        routing_calls=routing_calls,
                        evidence_extraction_calls=evidence_extraction_calls,
                        generation_calls=generation_calls,
                        review_calls=review_calls,
                        total_dialogue_calls=query_rewrite_calls + routing_calls + evidence_extraction_calls + generation_calls + review_calls,
                        fallback_used='sa_evidence_fallback',
                    )
                    return validate_response(fallback, len(citations), settings.api_token), citations
            elif use_mc_knn_fallback and has_options:
                mc_fb_json = knn_predict_mc(
                    safe_question,
                    context=context,
                    citation_count=len(citations),
                    exclude_ids=tuple(exclude_ids),
                )
                diag_record(
                    'llm_calls',
                    query_rewrite_calls=query_rewrite_calls,
                    routing_calls=routing_calls,
                    evidence_extraction_calls=evidence_extraction_calls,
                    generation_calls=generation_calls,
                    review_calls=review_calls,
                    total_dialogue_calls=query_rewrite_calls + routing_calls + evidence_extraction_calls + generation_calls + review_calls,
                    fallback_used='mc_knn_fallback',
                )
                return validate_response(mc_fb_json, len(citations), settings.api_token), citations
            raise first_exc

        result = json.loads(response)
        diag_record('generation', raw_draft_answer=str(result.get('answer') or ''))
        has_options = has_choice_options(safe_question)
        if has_options:
            response = verify_choice(safe_question, response, context, citations, client, settings, used_files, settings.choice_strategy)
        elif result['decision'] == 'answer':
            draft_response = response
            if enable_compiler:
                try:
                    draft_response = validate_response(
                        compile_response_json(
                            response,
                            safe_question,
                            context=context,
                            files=used_files,
                            primary_source_id=primary_source_id,
                            enable_anchors=getattr(settings, 'anchor_canonical', False),
                            enable_canonical=getattr(settings, 'anchor_canonical', False),
                            enable_neglect=getattr(settings, 'neglect_completion', False),
                            enable_support=getattr(settings, 'verified_support_append', False) or committed_append,
                            allow_scenario_patches=allow_patches,
                            committed_guide_append=committed_append,
                        ),
                        len(citations),
                        settings.api_token,
                    )
                except ValueError:
                    draft_response = response

            draft_control = primary_control_mention(str(result.get('answer') or ''))
            conflict = bool(scenario_reasoning and primary_source_id and draft_control and draft_control != primary_source_id)
            coverage_reasons = review_reasons(str(result.get('answer') or ''), context, conflict=conflict)
            should_review = not skip_review or bool(coverage_reasons)
            diag_record('generation', review_reasons=coverage_reasons, review_triggered=should_review)
            if should_review:
                review_context = context + '\nDRAFT_ANSWER=' + json.dumps(result['answer'], ensure_ascii=False)
                review_prompt = validate_prompt(builder(user_input=safe_question, context=review_context, citations=citations))
                try:
                    review_calls += 1
                    reviewed = generate_answer(client, review_prompt, len(citations), settings)
                    reviewed = validate_response(
                        complete_from_verified_evidence(reviewed, context, used_files, safe_question),
                        len(citations),
                        settings.api_token,
                    )
                    response = reviewed
                except GuardError:
                    raise
                except (ApiError, ValueError):
                    if not fail_soft:
                        raise
                    response = draft_response

            if enable_compiler:
                try:
                    compiled = compile_response_json(
                        response,
                        safe_question,
                        context=context,
                        files=used_files,
                        primary_source_id=primary_source_id,
                        enable_anchors=getattr(settings, 'anchor_canonical', False),
                        enable_canonical=getattr(settings, 'anchor_canonical', False),
                        enable_neglect=getattr(settings, 'neglect_completion', False),
                        enable_support=getattr(settings, 'verified_support_append', False) or committed_append,
                        allow_scenario_patches=allow_patches,
                        committed_guide_append=committed_append,
                    )
                    response = validate_response(compiled, len(citations), settings.api_token)
                except ValueError:
                    if not fail_soft:
                        raise
                    response = draft_response
    except GuardError:
        raise
    except ValueError as exc:
        raise ApiError(200, str(exc)) from exc

    diag_record(
        'llm_calls',
        query_rewrite_calls=query_rewrite_calls,
        routing_calls=routing_calls,
        evidence_extraction_calls=evidence_extraction_calls,
        generation_calls=generation_calls,
        review_calls=review_calls,
        total_dialogue_calls=query_rewrite_calls + routing_calls + evidence_extraction_calls + generation_calls + review_calls,
        fallback_used='none',
    )
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
        except GuardError:
            print(rejection_response())
            continue
        except (ApiError, ValueError) as exc:
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
    except GuardError:
        print(rejection_response())
        return 0
    except (ApiError, ValueError) as exc:
        print("请求未完成：" + short_error(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
