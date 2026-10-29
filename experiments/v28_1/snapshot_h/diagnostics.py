"""Opt-in, per-request diagnostics. Never records prompts or configurations."""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
import json

_active=ContextVar('rag_diagnostics',default=None)
_ALLOWED={'retrieval','router','fusion','prepared','evidence','generation','supplemental'}


@contextmanager
def capture_diagnostics(target: dict, secret: str = ''):
    token=_active.set((target,secret))
    try:yield target
    finally:_active.reset(token)


def record(stage: str, **values) -> None:
    active=_active.get()
    if active is None:return
    if stage not in _ALLOWED:raise ValueError('Unknown diagnostic stage')
    forbidden={'token','api_token','authorization','password','credentials','custom_prompt','prompt','config','hidden_prompt'}
    def unsafe(value):
        if isinstance(value,dict):return any(str(key).casefold() in forbidden or unsafe(item) for key,item in value.items())
        if isinstance(value,list):return any(unsafe(item) for item in value)
        return False
    if unsafe(values):raise ValueError('Sensitive diagnostic field')
    target,secret=active
    serialized=json.dumps(values,ensure_ascii=False)
    if secret:serialized=serialized.replace(secret,'[REDACTED]')
    target.setdefault(stage,{}).update(json.loads(serialized))


def source_ids(files) -> list[str]:
    return [str(file.get('metadata',{}).get('source_id') or file.get('file_id','')).casefold() for file in files]
