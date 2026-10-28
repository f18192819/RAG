"""通用工具：只记录必要的运行状态，不记录 Token、Prompt 或模型回复。"""

from __future__ import annotations

import logging


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )


def short_error(exc: Exception) -> str:
    """给终端展示简短错误类型，避免意外输出请求配置。"""
    return f"{exc.__class__.__name__}: {exc}"
