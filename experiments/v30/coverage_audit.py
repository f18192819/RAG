"""V30 Coverage Audit (Section 9 & Section 10): S_current vs S_commit and 5-level lexical/concept coverage across 226 short answers."""
from __future__ import annotations

import collections
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / "attack_defense_bot/attack_defense_bot"), str(HERE)]

from answer_compiler import (
    append_verified_course_support,
    canonical_terms,
    classify_short_answer_template,
    compile_answer,
    ensure_neglect_consequence,
    extract_question_anchors,
    resolve_control_id,
)
from control_routing import primary_control_mention
from eval_dataset import contains_expected_concepts, normalize_text
from evidence import is_chinese_question
from retrieval import guide_file, index


def score_concepts(text: str, concepts: list[list[str]]) -> tuple[bool, list[list[str]]]:
    norm_ans = normalize_text(text)
    ok, _, _ = contains_expected_concepts(norm_ans, concepts, 1.0)
    missed = []
    if not ok:
        for grp in concepts:
            if not any(normalize_text(t) in norm_ans for t in grp if normalize_text(t)):
                missed.append(grp)
    return ok, missed


def append_committed_guide_support(answer: str, question: str, committed_control_id: str) -> str:
    """S_commit (Section 9): Once primary control is committed to a registered guide-*, unconditionally append its course guide text."""
    cleaned = str(answer or "").strip()
    if not cleaned:
        return cleaned
    cid = str(committed_control_id or "").strip().casefold()
    if not cid.startswith("guide-"):
        return cleaned
    guides = {doc["id"]: doc for doc in index()[0] if doc["id"].startswith("guide-")}
    doc = guides.get(cid)
    if not doc:
        return cleaned
    zh = is_chinese_question(question)
    quote = str(doc.get("text_zh" if zh else "text_en") or doc.get("text") or "").strip()
    if not quote:
        return cleaned
    if normalize_text(quote) in normalize_text(cleaned):
        return cleaned
    heading = "课程参考：" if zh else "Course reference: "
    return f"{cleaned}\n\n{heading}{quote}"


def run_coverage_audit() -> dict[str, Any]:
    manifest = json.loads((HERE / "frozen_shadow_manifest.json").read_text(encoding="utf-8"))
    canonical_controls = manifest["canonical_controls"]
    guides = {doc["id"]: doc for doc in index()[0] if doc["id"].startswith("guide-")}

    rows = [json.loads(l) for l in (ROOT / "public_dataset.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    sa_rows = [r for r in rows if r["expected"].get("concepts")]

    v18_routes = {
        json.loads(l)["id"]: json.loads(l)["selected"][0]
        for l in (ROOT / "output/route_audit_v18_full_catalog.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()
    }

    # Load saved real LLM drafts from validation and holdout where available
    saved_drafts: dict[str, str] = {}
    for split in ("validation", "holdout"):
        p = ROOT / f"experiments/v28_1/results/A_{split}_details.jsonl"
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    item = json.loads(line)
                    if item.get("question_type") == "short_answer":
                        saved_drafts[item["question_id"]] = item.get("generation", {}).get("answer", "")

    levels = [
        "1_question_only",
        "2_draft_only_raw_route",
        "3_draft_plus_canonical_raw_route",
        "4_draft_plus_committed_guide_raw_route",
        "5_question_plus_committed_guide_raw_route",
        "6_S_current_7cond_on_true_control",
        "7_S_commit_unconditional_on_true_control",
        "8_full_v30_compiler_with_S_commit_on_true_control",
    ]
    results: dict[str, Any] = {}

    for lvl in levels:
        both_ok = 0
        official_ok = 0
        ctrl_ok = 0
        correct_ctrl_keyword_miss = 0
        wrong_ctrl_accidental_pass = 0
        wrong_ctrl_fail = 0
        by_tpl: dict[str, dict[str, int]] = {}
        misses_detail = []

        for r in sa_rows:
            qid = r["id"]
            q_text = r["input"]["text"]
            tpl = classify_short_answer_template(q_text)
            zh = is_chinese_question(q_text)
            true_ctrl = canonical_controls[r["provenance"]["augmentation_group"]]
            raw_route = v18_routes.get(qid, true_ctrl)

            by_tpl.setdefault(tpl, {"total": 0, "both_correct": 0, "official_correct": 0, "control_correct": 0})
            by_tpl[tpl]["total"] += 1

            # Determine which control is active for this level
            active_ctrl = true_ctrl if "true_control" in lvl else raw_route
            g_doc = guides.get(active_ctrl, {})
            g_quote = g_doc.get("text_zh" if zh else "text_en", "")
            draft = saved_drafts.get(qid) or g_quote
            anchors = extract_question_anchors(q_text)
            ct = canonical_terms(active_ctrl, "zh" if zh else "en", anchors.get("control_name") or "")
            canon_str = f"{ct['formatted']} {ct['mechanism']}"
            if tpl == "T1_neglect":
                canon_str += " 从而使相关威胁更容易转化为实际事件。"

            if lvl == "1_question_only":
                cand_text = q_text
                is_ctrl_right = bool(resolve_control_id(q_text) == true_ctrl)
            elif lvl == "2_draft_only_raw_route":
                cand_text = draft
                is_ctrl_right = (active_ctrl == true_ctrl)
            elif lvl == "3_draft_plus_canonical_raw_route":
                cand_text = f"{canon_str}\n{draft}"
                is_ctrl_right = (active_ctrl == true_ctrl)
            elif lvl == "4_draft_plus_committed_guide_raw_route":
                cand_text = append_committed_guide_support(f"{ct['formatted']}：{draft}", q_text, active_ctrl)
                if tpl == "T1_neglect":
                    cand_text = ensure_neglect_consequence(cand_text, tpl)
                is_ctrl_right = (active_ctrl == true_ctrl)
            elif lvl == "5_question_plus_committed_guide_raw_route":
                cand_text = append_committed_guide_support(f"{q_text}\n{canon_str}", q_text, active_ctrl)
                is_ctrl_right = (active_ctrl == true_ctrl)
            elif lvl == "6_S_current_7cond_on_true_control":
                files = [guide_file(g_doc)] if g_doc else []
                ctx = json.dumps({"validated_evidence": [{"source": 1, "fact": g_quote, "quote": g_quote}]}, ensure_ascii=False)
                # Simulate a terse LLM paraphrase draft that has zero lexical overlap with quote
                terse_draft = f"{ct['formatted']}"
                if tpl == "T1_neglect":
                    terse_draft = ensure_neglect_consequence(terse_draft, tpl)
                cand_text = append_verified_course_support(terse_draft, q_text, ctx, files, active_ctrl)
                is_ctrl_right = (active_ctrl == true_ctrl)
            elif lvl == "7_S_commit_unconditional_on_true_control":
                terse_draft = f"{ct['formatted']}"
                if tpl == "T1_neglect":
                    terse_draft = ensure_neglect_consequence(terse_draft, tpl)
                cand_text = append_committed_guide_support(terse_draft, q_text, active_ctrl)
                is_ctrl_right = (active_ctrl == true_ctrl)
            else:
                files = [guide_file(g_doc)] if g_doc else []
                ctx = json.dumps({"validated_evidence": [{"source": 1, "fact": g_quote, "quote": g_quote}]}, ensure_ascii=False)
                compiled = compile_answer(
                    question=q_text,
                    draft_answer=draft,
                    context=ctx,
                    files=files,
                    primary_source_id=active_ctrl,
                    enable_anchors=True,
                    enable_canonical=True,
                    enable_neglect=True,
                    enable_support=True,
                )
                cand_text = append_committed_guide_support(compiled, q_text, active_ctrl)
                is_ctrl_right = (active_ctrl == true_ctrl) and (primary_control_mention(cand_text) in {true_ctrl, None})

            ok, missed = score_concepts(cand_text, r["expected"]["concepts"])
            if ok:
                official_ok += 1
                by_tpl[tpl]["official_correct"] += 1
            if is_ctrl_right:
                ctrl_ok += 1
                by_tpl[tpl]["control_correct"] += 1
            if ok and is_ctrl_right:
                both_ok += 1
                by_tpl[tpl]["both_correct"] += 1
            elif is_ctrl_right and not ok:
                correct_ctrl_keyword_miss += 1
                misses_detail.append(
                    {
                        "id": qid,
                        "template": tpl,
                        "true_control": true_ctrl,
                        "active_control": active_ctrl,
                        "reason": "correct_control_but_keyword_miss",
                        "missed_groups": missed,
                    }
                )
            elif (not is_ctrl_right) and ok:
                wrong_ctrl_accidental_pass += 1
            else:
                wrong_ctrl_fail += 1
                misses_detail.append(
                    {
                        "id": qid,
                        "template": tpl,
                        "true_control": true_ctrl,
                        "active_control": active_ctrl,
                        "reason": "wrong_control",
                        "missed_groups": missed,
                    }
                )

        results[lvl] = {
            "total": len(sa_rows),
            "official_score_correct": official_ok,
            "official_score_accuracy": round(official_ok / len(sa_rows), 4),
            "primary_control_correct": ctrl_ok,
            "primary_control_accuracy": round(ctrl_ok / len(sa_rows), 4),
            "strict_both_correct": both_ok,
            "strict_both_accuracy": round(both_ok / len(sa_rows), 4),
            "correct_control_but_keyword_miss": correct_ctrl_keyword_miss,
            "wrong_control_accidental_pass": wrong_ctrl_accidental_pass,
            "wrong_control_and_fail": wrong_ctrl_fail,
            "by_template": by_tpl,
            "sample_misses": misses_detail[:12],
        }

    (HERE / "results").mkdir(parents=True, exist_ok=True)
    (HERE / "results/coverage_audit_summary.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    for k, v in results.items():
        print(
            f"{k}: official={v['official_score_correct']}/226 ({v['official_score_accuracy']:.2%}), "
            f"control={v['primary_control_correct']}/226, both={v['strict_both_correct']}/226, "
            f"kw_miss={v['correct_control_but_keyword_miss']}, wrong_ctrl={v['wrong_control_and_fail']}"
        )
    return results


if __name__ == "__main__":
    run_coverage_audit()

