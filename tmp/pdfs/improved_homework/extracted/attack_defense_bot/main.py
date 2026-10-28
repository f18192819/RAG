"""入口：search → context → prompt → guard → dialogue。"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

try:  # 同时支持包模式和直接运行模式。
    from .api_client import ApiError, RagApiClient
    from .config import Settings, load_settings
    from .data_processor import prepare_context, files_to_citations, select_relevant_files
    from .guard import GuardError, validate_prompt, validate_user_input, validate_response
    from .prompt_builder import build_prompt
    from .utils import configure_logging, short_error
except ImportError:  # pragma: no cover - `python main.py` 时使用
    from api_client import ApiError, RagApiClient
    from config import Settings, load_settings
    from data_processor import prepare_context, files_to_citations, select_relevant_files
    from guard import GuardError, validate_prompt, validate_user_input, validate_response
    from prompt_builder import build_prompt
    from utils import configure_logging, short_error


LOG = logging.getLogger(__name__)


def answer_question(question: str, settings: Settings, show_prompt: bool = False) -> tuple[str, Sequence[str]]:
    """执行完整链路；返回模型回答和脱敏引用列表。"""
    safe_question = validate_user_input(question)
    client = RagApiClient(settings)


    files = client.search(
        settings.database_name,
        safe_question,
        top_k=settings.top_k,
        metric_type=settings.metric_type,
        score_threshold=settings.score_threshold,
    )
    relevant_files = select_relevant_files(
        files,
        min_score=settings.score_threshold,
        max_files=settings.context_max_files,
        query=safe_question,
    )
    context, used_files = prepare_context(
        relevant_files,
        max_chars=settings.context_max_chars,
        max_files=settings.context_max_files,
    )
    citations = files_to_citations(used_files, max_files=settings.context_max_files)
    if settings.api_token:
        citations = [label.replace(settings.api_token, "[REDACTED]") for label in citations]

    prompt = build_prompt(user_input=safe_question, context=context, citations=citations)
    safe_prompt = validate_prompt(prompt)

    response = client.dialogue(
        user_input="",
        custom_prompt=safe_prompt,
        temperature=settings.temperature,
        max_tokens=settings.max_tokens,
    )
    try:
        response = validate_response(response, len(citations), settings.api_token)
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
