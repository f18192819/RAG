"""Read authentication from the environment or a private, external file."""
from __future__ import annotations
import json
import os
from pathlib import Path


def credential_path() -> Path:
    configured=os.getenv('RAG_PLATFORM_TOKEN_FILE') or os.getenv('RAG_TOKEN_FILE')
    return Path(configured).expanduser() if configured else Path.home()/'.config/rag/student.token.json'


def load_credentials(path: Path | None = None) -> dict:
    location=(path or credential_path()).resolve()
    repository=Path(__file__).resolve().parents[2]
    if location.is_relative_to(repository):
        raise ValueError('Credential files must be outside the repository')
    value=json.loads(location.read_text(encoding='utf-8-sig'))
    if not isinstance(value,dict) or not isinstance(value.get('token'),str) or not value['token'].strip():
        raise ValueError('Invalid external credential file')
    return value
