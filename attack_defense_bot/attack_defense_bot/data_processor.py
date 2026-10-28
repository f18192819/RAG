"""检索清洗、轻量混合重排、去重和可追溯的预算裁剪。"""
from __future__ import annotations
import math
import re
import unicodedata
from html import unescape
from typing import Any, Dict, Iterable, List
try:
    from .guard import instruction_risks
    from .evidence import contains_source_instruction
except ImportError:
    from guard import instruction_risks
    from evidence import contains_source_instruction


def _score(item: Dict[str, Any]) -> float:
    try:
        value = float(item.get("score", 0))
        return value if math.isfinite(value) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _clean_text(value: Any) -> str:
    normalized = unicodedata.normalize('NFKC', unescape(str(value or '')))
    normalized = ''.join(c for c in normalized if unicodedata.category(c) != 'Cf' and
                         (unicodedata.category(c) != 'Cc' or c in '\n\r\t'))
    return ' '.join(normalized.split())


def _terms(text: str) -> set[str]:
    text = unicodedata.normalize("NFKC", text).lower()
    words = set(re.findall(r"[a-z0-9][a-z0-9_-]+", text))
    for run in re.findall(r"[\u4e00-\u9fff]+", text):
        words.update(run[i:i+2] for i in range(len(run)-1))
    return words


def select_relevant_files(files: Iterable[Dict[str, Any]], min_score: float = 0.0,
                          max_files: int = 5, query: str = "") -> List[Dict[str, Any]]:
    candidates = []
    seen = set()
    ordered = sorted((item for item in files if isinstance(item, dict)), key=_score, reverse=True)
    for item in ordered:
        if not isinstance(item, dict) or _score(item) < min_score:
            continue
        raw = item.get("text")
        if not isinstance(raw, str) or not raw.strip():
            continue
        # 检索污染按段隔离；解释/分析注入的教材段落仍可保留。
        paragraphs = re.split(r"\n\s*\n|\r?\n", raw)
        paragraphs = [p for p in paragraphs if not contains_source_instruction(p)]
        text = _clean_text("\n".join(paragraphs))
        key = unicodedata.normalize("NFKC", text).casefold()
        if not text or key in seen:
            continue
        seen.add(key)
        candidate = dict(item)
        candidate["text"] = text
        candidates.append(candidate)
    query_terms = _terms(query)
    def rank(item: Dict[str, Any]) -> float:
        overlap = len(query_terms & _terms(item["text"])) / max(1, len(query_terms))
        return _score(item) + 0.15 * overlap
    candidates.sort(key=rank, reverse=True)
    return candidates[:max(0, max_files)]


def prepare_context(files: Iterable[Dict[str, Any]], max_chars: int = 6000,
                    max_files: int = 5) -> tuple[str, List[Dict[str, Any]]]:
    """返回实际进入 Prompt 的材料；上下文和引用使用同一个编号序列。"""
    if max_chars <= 0 or max_files <= 0:
        return "", []
    blocks, used = [], []
    budget = max_chars
    for item in files:
        if len(used) >= max_files:
            break
        text = _clean_text(item.get("text"))
        if not text:
            continue
        prefix = f"[资料 {len(used)+1}]\n"
        separator = 2 if blocks else 0
        remaining = budget - len(prefix) - separator
        if remaining <= 0:
            break
        clipped = text[:remaining]
        blocks.append(prefix + clipped)
        kept = dict(item)
        kept["text"] = clipped
        used.append(kept)
        budget -= len(prefix) + len(clipped) + separator
    return "\n\n".join(blocks), used


def extract_context(files: Iterable[Dict[str, Any]], max_chars: int = 6000, max_files: int = 5) -> str:
    selected = select_relevant_files(files, max_files=max_files)
    return prepare_context(selected, max_chars, max_files)[0]


def files_to_citations(files: Iterable[Dict[str, Any]], max_files: int = 5) -> List[str]:
    citations = []
    for item in files:
        if len(citations) >= max_files:
            break
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        source = metadata.get("source_id") or metadata.get("source") or metadata.get("title") or item.get("file_id")
        # 元数据同样不可信；限制单行长度，并隐藏凭据类字段。
        label = _clean_text(source)[:100] or "未标注来源"
        if instruction_risks(label) or re.search(r"(?i)(?:bearer|token|password|api.?key)\s*[:= ]", label):
            label = "来源标签已隐藏"
        citations.append(f"[{len(citations)+1}] {label}")
    return citations
