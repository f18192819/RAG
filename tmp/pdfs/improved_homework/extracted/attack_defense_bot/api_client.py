"""与课程后端通信的最小客户端。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlsplit
import ipaddress
import os

import requests

try:  # 允许 `python main.py` 与 `python -m attack_defense_bot.main` 两种启动方式。
    from .config import Settings, require_token
except ImportError:  # pragma: no cover - 直接运行脚本时使用
    from config import Settings, require_token


class ApiError(RuntimeError):
    """后端返回非成功状态时抛出；错误信息中不包含 Token。"""

    def __init__(self, status_code: int, detail: str, request_id: Optional[str] = None) -> None:
        message = f"API 请求失败（HTTP {status_code}）：{detail}"
        if request_id:
            message += f"；request_id={request_id}"
        super().__init__(message)
        self.status_code = status_code
        self.request_id = request_id


class RagApiClient:
    def __init__(self, settings: Settings) -> None:
        require_token(settings)
        self._base_url = settings.api_base_url
        self._timeout = settings.timeout_seconds
        self._session = requests.Session()
        # 校园 VPN 提供 IP 路由；避免继承过期的互联网代理而将内网请求发往错误端口。
        try:
            private_target = ipaddress.ip_address(urlsplit(self._base_url).hostname or "").is_private
        except ValueError:
            private_target = False
        self._session.trust_env = not private_target or os.getenv("RAG_USE_ENV_PROXY", "0") == "1"
        self._session.headers.update(
            {
                "Authorization": f"Bearer {settings.api_token}",
                "Content-Type": "application/json",
            }
        )

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            response = self._session.post(self._base_url + path, json=payload, timeout=self._timeout)
        except requests.RequestException as exc:
            raise ApiError(0, f"网络请求失败：{exc.__class__.__name__}") from exc
        return self._decode_response(response)

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            response = self._session.get(self._base_url + path, params=params, timeout=self._timeout)
        except requests.RequestException as exc:
            raise ApiError(0, f"网络请求失败：{exc.__class__.__name__}") from exc
        return self._decode_response(response)

    def _decode_response(self, response: requests.Response) -> Dict[str, Any]:
        request_id = response.headers.get("X-Request-ID")
        try:
            body: Any = response.json()
        except ValueError:
            body = {}
        if not response.ok:
            detail = body.get("detail", "服务器未返回可解析的错误信息") if isinstance(body, dict) else "服务器请求失败"
            token = self._session.headers.get("Authorization", "").removeprefix("Bearer ")
            safe_detail = str(detail).replace(token, "[REDACTED]") if token else str(detail)
            raise ApiError(response.status_code, safe_detail[:300], request_id)
        if not isinstance(body, dict):
            raise ApiError(response.status_code, "服务器返回格式不是 JSON 对象", request_id)
        return body

    def search(
        self,
        db_name: str,
        query: str,
        top_k: int = 5,
        metric_type: str = "cosine",
        score_threshold: float = 0.0,
        expr: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """调用 PPT 中的“相似文件检索”接口，并只返回 files 列表。

        ``expr`` 与 PPT 的 ``file_id == <id>`` 筛选写法兼容；不需要筛选时传
        ``None``。PPT 中的 ``token`` 字段由客户端自动写入 Bearer Header。
        """

        safe_db_name = quote(db_name, safe="_")
        payload: Dict[str, Any] = {
            "query": query,
            "top_k": top_k,
            "metric_type": metric_type,
            "score_threshold": score_threshold,
        }
        if expr:
            payload["expr"] = expr
        body = self._post(f"/databases/{safe_db_name}/search", payload)
        files = body.get("files", [])
        if not isinstance(files, list):
            raise ApiError(200, "search 响应的 files 不是列表")
        return [item for item in files if isinstance(item, dict)]

    def list_files(self, database_name: str, limit: int = 3) -> List[Dict[str, Any]]:
        """可选诊断函数：确认公共库可读，不用于批量下载语料。"""

        safe_database_name = quote(database_name, safe="_")
        body = self._get(
            f"/databases/{safe_database_name}/files",
            {"offset": 0, "limit": max(1, min(int(limit), 1000))},
        )
        files = body.get("files", [])
        if not isinstance(files, list):
            raise ApiError(200, "files 响应不是列表")
        return [item for item in files if isinstance(item, dict)]

    def create_database(self, database_name: str, metric_type: str = "cosine") -> str:
        """创建个人知识库，返回后端实际使用的完整库名。

        对应上传示例之前的建库步骤。学生不能创建或覆盖 ``common_dataset``。
        """
        if database_name == "common_dataset":
            raise ValueError("common_dataset 是课程公共只读库，不能创建或覆盖")
        payload = {"database_name": database_name, "metric_type": metric_type}
        body = self._post("/databases", payload)
        actual_name = body.get("database_name")
        if not isinstance(actual_name, str) or not actual_name:
            raise ApiError(200, "创建数据库响应缺少 database_name")
        return actual_name

    def upload_files(self, db_name: str, files: List[Dict[str, Any]]) -> List[int]:
        """调用 PPT 中的“向数据库上传文件”接口。

        ``files`` 的每项为 ``{"file": "文本", "metadata": {...}}``。只能上传到
        自己的个人库，不能上传到 ``common_dataset``。
        """
        if db_name == "common_dataset":
            raise ValueError("common_dataset 是公共只读库，不能上传")
        if not files:
            raise ValueError("files 不能为空")
        safe_db_name = quote(db_name, safe="_")
        body = self._post(f"/databases/{safe_db_name}/files", {"files": files})
        file_ids = body.get("file_ids", [])
        if not isinstance(file_ids, list):
            raise ApiError(200, "上传响应的 file_ids 不是列表")
        return [int(file_id) for file_id in file_ids]

    def dialogue(
        self,
        user_input: str,
        custom_prompt: str = "",
        temperature: float = 0.2,
        max_tokens: int = 300,
    ) -> str:
        """调用 PPT 中的“大模型对话”接口。"""

        body = self._post(
            "/dialogue",
            {
                "user_input": user_input,
                "custom_prompt": custom_prompt,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        response = body.get("response")
        if not isinstance(response, str):
            raise ApiError(200, "dialogue 响应缺少字符串 response")
        return response
