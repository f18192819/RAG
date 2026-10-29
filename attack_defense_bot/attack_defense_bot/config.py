from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict
from types import MappingProxyType

RRF_WEIGHTS=MappingProxyType({'exact':8.0,'options':4.5,'explicit_named':4.5,
    'contrastive':1.0,'dense':1.3,'public_bm25':1.4,'course_bm25':1.4,
    'local_bm25':1.1,'personal':1.1})


PACKAGE_DIR = Path(__file__).resolve().parent
ENV_FILE = PACKAGE_DIR / ".env"


def _read_dotenv(path: Path) -> Dict[str, str]:
    """读取最小 .env 格式，避免为模板额外引入 dotenv 依赖。"""
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _get_int(name: str, values: Dict[str, str], default: int) -> int:
    raw_value = os.getenv(name, values.get(name, str(default)))
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} 必须是整数") from exc


def _get_float(name: str, values: Dict[str, str], default: float) -> float:
    raw_value = os.getenv(name, values.get(name, str(default)))
    try:
        return float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} 必须是数字") from exc


@dataclass(frozen=True)
class Settings:
    api_base_url: str
    api_token: str = field(repr=False)
    database_name: str
    metric_type: str
    top_k: int
    score_threshold: float
    context_max_files: int
    context_max_chars: int
    timeout_seconds: int
    temperature: float
    max_tokens: int
    personal_database_name: str = ''
    choice_strategy: str = 'rag'
    rerank_margin: float = 0.15
    rerank_min_score: float = 0.65
    supplemental_retrieval: bool = True
    query_representation: bool = True
    contrastive_rerank: bool = True
    production_profile: str = 'A'
    candidate_retention: bool = False
    answer_completeness: bool = False


def load_settings() -> Settings:
    """优先使用环境变量；未设置时读取当前目录下的 .env。"""
    values = _read_dotenv(ENV_FILE)
    profile_path=PACKAGE_DIR/'pipeline_profile.json'
    profile=json.loads(profile_path.read_text(encoding='utf-8')) if profile_path.exists() else {}
    api_base_url = os.getenv("RAG_API_BASE_URL", values.get("RAG_API_BASE_URL", "http://10.1.0.220:9002/api"))
    api_token = os.getenv("RAG_API_TOKEN", values.get("RAG_API_TOKEN", ""))
    if not api_token:
        try:
            try:from .credentials import load_credentials
            except ImportError:from credentials import load_credentials
            external=os.getenv('RAG_TOKEN_FILE',values.get('RAG_TOKEN_FILE',''))
            api_token=load_credentials(Path(external).expanduser() if external else None)['token']
        except FileNotFoundError:
            api_token=''
    database_name = os.getenv("RAG_DATABASE_NAME", values.get("RAG_DATABASE_NAME", "common_dataset"))
    metric_type = os.getenv("RAG_METRIC_TYPE", values.get("RAG_METRIC_TYPE", "cosine"))
    settings = Settings(
        api_base_url=api_base_url.rstrip("/"),
        api_token=api_token.strip(),
        database_name=database_name.strip(),
        metric_type=metric_type.strip() or "cosine",
        top_k=_get_int("RAG_TOP_K", values, 5),
        score_threshold=_get_float("RAG_SCORE_THRESHOLD", values, 0.0),
        context_max_files=_get_int("RAG_CONTEXT_MAX_FILES", values, 5),
        context_max_chars=_get_int("RAG_CONTEXT_MAX_CHARS", values, 6000),
        timeout_seconds=_get_int("RAG_TIMEOUT_SECONDS", values, 90),
        temperature=_get_float("RAG_TEMPERATURE", values, 0),
        max_tokens=_get_int("RAG_MAX_TOKENS", values, 1000),
        personal_database_name=os.getenv('RAG_PERSONAL_DATABASE', values.get('RAG_PERSONAL_DATABASE', '')).strip(),
        choice_strategy=os.getenv('RAG_CHOICE_STRATEGY',values.get('RAG_CHOICE_STRATEGY','rag')).strip(),
        rerank_margin=_get_float('RAG_RERANK_MARGIN',values,0.15),
        rerank_min_score=_get_float('RAG_RERANK_MIN_SCORE',values,0.65),
        supplemental_retrieval=os.getenv('RAG_SUPPLEMENTAL_RETRIEVAL',values.get('RAG_SUPPLEMENTAL_RETRIEVAL','true')).lower()=='true',
        query_representation=os.getenv('RAG_QUERY_REPRESENTATION',str(profile.get('query_representation',True))).lower()=='true',
        contrastive_rerank=os.getenv('RAG_CONTRASTIVE_RERANK',str(profile.get('contrastive_rerank',True))).lower()=='true',
        production_profile=os.getenv('RAG_PRODUCTION_PROFILE',profile.get('production_profile','A')),
        candidate_retention=os.getenv('RAG_CANDIDATE_RETENTION',str(profile.get('candidate_retention',False))).lower()=='true',
        answer_completeness=os.getenv('RAG_ANSWER_COMPLETENESS',str(profile.get('answer_completeness',False))).lower()=='true',
    )
    if not 1 <= settings.top_k <= 50 or not 1 <= settings.context_max_files <= settings.top_k:
        raise ValueError("top_k 必须在 1..50，max_files 必须在 1..top_k")
    if not 100 <= settings.context_max_chars <= 6000:
        raise ValueError("context_max_chars 必须在 100..6000")
    if not 1 <= settings.timeout_seconds <= 180 or not 64 <= settings.max_tokens <= 4096:
        raise ValueError("请求超时或输出长度参数越界")
    if not 0 <= settings.temperature <= 1 or not 0 <= settings.score_threshold <= 1:
        raise ValueError("temperature 和 score_threshold 必须在 0..1")
    if not 0<=settings.rerank_margin<=1 or not 0<=settings.rerank_min_score<=1:
        raise ValueError('Reranking settings must be in 0..1')
    if settings.production_profile not in {'A','candidate'}:
        raise ValueError('Unknown production profile')
    return settings


def require_token(settings: Settings) -> None:
    if not settings.api_token:
        raise ValueError(
            "未配置个人 Token。请复制 .env.example 为 .env，并填写 RAG_API_TOKEN；不要把 Token 写入代码。"
        )
    if not settings.database_name:
        raise ValueError("RAG_DATABASE_NAME 不能为空")
