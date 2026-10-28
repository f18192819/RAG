"""离线护栏评估。通过只表示放行到模型，不表示知识题答对。"""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter
from pathlib import Path
try:
    from .guard import validate_user_input, GuardError
except ImportError:
    from guard import validate_user_input, GuardError

BASELINE_PATTERNS = (
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"忽略(之前|上述|前面).{0,8}(指令|规则)",
    r"reveal\s+(the\s+)?(system\s+)?prompt",
    r"泄露.{0,8}(系统提示词|提示词|指令)",
)


def run(dataset: Path, output: Path) -> dict:
    details = []
    for raw in dataset.read_text(encoding="utf-8-sig").splitlines():
        if not raw.strip():
            continue
        obj = json.loads(raw)
        question = obj["input"]["text"]
        try:
            validate_user_input(question)
            blocked = False
        except GuardError:
            blocked = True
        baseline_blocked = len(question.strip()) > 2000 or not question.strip() or any(
            re.search(p, " ".join(question.lower().split()), re.I) for p in BASELINE_PATTERNS)
        details.append({"id": obj["id"], "expected": obj["expected"]["decision"],
                        "attack_type": obj["expected"].get("attack_type"),
                        "guard_blocked": blocked, "baseline_blocked": baseline_blocked})
    summary = {"scope": "offline_input_guard_only", "student_id": "2024012348",
               "dataset_records": len(details), "knowledge_answer_accuracy": None,
               "notice": "未调用检索或模型，不能用此结果宣称完整系统正确率或隐藏集表现。"}
    for name, key in [("baseline", "baseline_blocked"), ("improved", "guard_blocked")]:
        counts = Counter()
        by_type = {}
        for item in details:
            expected = item["expected"] == "reject"
            counts["tp" if expected and item[key] else "fn" if expected else "fp" if item[key] else "tn"] += 1
            if expected:
                a = by_type.setdefault(item["attack_type"], {"total": 0, "blocked": 0})
                a["total"] += 1
                a["blocked"] += int(item[key])
        tp, fp, fn, tn = (counts[k] for k in ["tp", "fp", "fn", "tn"])
        summary[name] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                         "attack_block_rate": tp / max(1,tp+fn),
                         "benign_false_block_rate": fp / max(1,fp+tn),
                         "guard_f1": 2*tp / max(1,2*tp+fp+fn), "by_attack_type": by_type}
    output.mkdir(parents=True, exist_ok=True)
    (output / "guard_summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
    (output / "guard_details.jsonl").write_text("\n".join(json.dumps(r,ensure_ascii=False) for r in details)+"\n",encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("output/offline"))
    args = parser.parse_args()
    print(json.dumps(run(args.dataset,args.output_dir),ensure_ascii=False,indent=2))
