"""可选扩展：仅在本地内存保存简短的多轮对话摘要。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class ConversationMemory:
    max_turns: int = 3
    _turns: List[Tuple[str, str]] = field(default_factory=list)

    def add_turn(self, user_input: str, assistant_response: str) -> None:
        self._turns.append((user_input, assistant_response))
        self._turns = self._turns[-self.max_turns :]

    def summary(self) -> str:
        return "\n".join(f"用户：{user}\n助手：{assistant}" for user, assistant in self._turns)