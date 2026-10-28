"""联网后验证建库/上传/公共检索/对话/完整链路，保存脱敏证据。"""
from __future__ import annotations
import argparse
import json
from dataclasses import replace
from datetime import datetime, timezone, timedelta
from pathlib import Path
try:
    from .api_client import RagApiClient, ApiError
    from .config import load_settings
    from .main import answer_question
except ImportError:
    from api_client import RagApiClient, ApiError
    from config import load_settings
    from main import answer_question


def run(output: Path, timeout: int = 8) -> dict:
    settings = replace(load_settings(), timeout_seconds=timeout)
    client = RagApiClient(settings)
    report = {"student_id": "2024012348", "timestamp": datetime.now(timezone(timedelta(hours=9))).isoformat(),
              "base_url": settings.api_base_url, "steps": [], "public_database_mutated": False}
    def step(name, action):
        try:
            result = action()
            report["steps"].append({"step": name, "status": "passed", "result": result})
            return result
        except (ApiError, ValueError) as exc:
            report["steps"].append({"step": name, "status": "failed", "error": str(exc)})
            return None
    databases = step("list_databases", lambda: client._get("/databases").get("databases", []))
    if databases is not None:
        step("public_corpus_read", lambda: {"record_count": len(client.list_files("common_dataset",3))})
        step("public_search", lambda: {"record_count":len(client.search("common_dataset","如何降低提示词注入风险？",top_k=3))})
        step("dialogue", lambda: {"nonempty_response":bool(client.dialogue("请用一句话解释最小权限原则。", max_tokens=150).strip())})
        requested = "rag_demo_2024012348"
        actual = "student_2024012348_" + requested
        if actual not in databases:
            actual = step("create_personal_database", lambda: client.create_database(requested))
        else:
            report["steps"].append({"step":"create_personal_database","status":"passed","result":"reuse_existing_owned_database"})
        if actual:
            existing = step("list_personal_files", lambda: client.list_files(actual,100))
            if existing is not None and not any(f.get("metadata",{}).get("source_id")=="self-authored-2024012348-01" for f in existing):
                step("upload_personal_document", lambda: {"uploaded_count":len(client.upload_files(actual,[{
                    "file":"最小权限原则要求仅授予完成任务所需的权限，并定期复核和及时撤销。提示词注入防护应区分系统策略与外部数据，对检索内容隔离并核验引用。",
                    "metadata":{"source_id":"self-authored-2024012348-01","description":"本人整理的课程概念摘要，用于验证个人库上传接口，不含测试集答案。"}}]))})
            elif existing is not None:
                report["steps"].append({"step":"upload_personal_document","status":"passed","result":"reuse_existing_demo_document"})
            step("personal_search", lambda: {"record_count":len(client.search(actual,"最小权限",top_k=3))})
        result = step("end_to_end", lambda: answer_question("什么是最小权限原则？", settings))
        if result is not None:
            report["steps"][-1]["result"] = {"response_json_valid":True,"citation_count":len(result[1])}
    else:
        for name in ["public_corpus_read","public_search","dialogue","create_personal_database","upload_personal_document","personal_search","end_to_end"]:
            report["steps"].append({"step":name,"status":"not_run","reason":"课程接口不可达或认证失败"})
    # 只保留数量，不把语料内容写入证据。
    for item in report["steps"]:
        if item["step"] == "list_personal_files" and item["status"] == "passed":
            item["result"] = {"record_count":len(item["result"])}
    report["all_passed"] = all(s["status"]=="passed" for s in report["steps"])
    output.parent.mkdir(parents=True,exist_ok=True)
    encoded = json.dumps(report,ensure_ascii=False,indent=2).replace(settings.api_token,"[REDACTED]")
    output.write_text(encoded+"\n",encoding="utf-8")
    print(encoded)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,default=Path("output/api_smoke.json"))
    parser.add_argument("--timeout",type=int,default=8)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.output,args.timeout)["all_passed"] else 1)
