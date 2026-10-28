"""配置本人 Token：只写本地 .env，不回显任何凭据。"""
from __future__ import annotations
import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args()
    obj = json.loads(args.token_file.read_text(encoding="utf-8-sig"))
    if str(obj.get("student_id")) != "2024012348":
        raise SystemExit("Token 文件学号不匹配")
    token = obj.get("token")
    if not isinstance(token,str) or not token.strip() or any(c.isspace() for c in token):
        raise SystemExit("Token 格式无效")
    base = Path(__file__).resolve().parent
    template = (base / ".env.example").read_text(encoding="utf-8-sig")
    lines = ["RAG_API_TOKEN="+token if line.startswith("RAG_API_TOKEN=") else line
             for line in template.splitlines()]
    (base / ".env").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("学号 2024012348 的本地 .env 已配置；请勿共享该文件。")


if __name__ == "__main__":
    main()
