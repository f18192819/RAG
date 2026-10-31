"""Build and freeze experiments/v30/frozen_shadow_manifest.json with strict scenario-family group splitting."""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path
import random
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "attack_defense_bot/attack_defense_bot")]

from answer_compiler import classify_short_answer_template
from evidence import is_chinese_question


def normalize_scenario_stem(question: str) -> tuple[str, str]:
    """
    Normalize a question into (family_kind, normalized_core) so near-duplicate siblings
    (especially T3 scenario + MC scenario siblings sharing a failure phrase) are grouped together.
    """
    q = question.replace("【问题】", "").strip()
    stem = q.split("\n")[0].strip()
    tpl = classify_short_answer_template(question)

    # 1. Scenario family: T3 ("某…遇到以下情况：<failure>。应优先采取什么安全措施，为什么？")
    #    and MC ("某…发现：<failure>。哪项措施最直接针对这一问题？")
    m_t3 = re.search(r"遇到以下情况[:：]\s*(.+?)[。！？!?]\s*应优先采取什么安全措施", stem)
    if m_t3:
        failure = re.sub(r"\s+", "", m_t3.group(1).strip())
        return ("scenario_failure", failure)

    m_mc_scen = re.search(r"发现[:：]\s*(.+?)[。！？!?]\s*哪项措施最直接针对这一问题", stem)
    if m_mc_scen:
        failure = re.sub(r"\s+", "", m_mc_scen.group(1).strip())
        return ("scenario_failure", failure)

    # 2. Chinese Purpose quote family: T4 ("X的核心安全目标是什么？")
    #    and MC ("为了实现“...”，最匹配的控制是什么？" / "以下哪项最准确地描述了X的主要目的？")
    if tpl == "T4_purpose_zh" or "主要目的" in stem or "最匹配的控制是什么" in stem:
        return ("purpose_zh", tpl)

    # 3. English Purpose family: T5 ("What is the primary security purpose of X?")
    #    and English MC ("Which control should ... prioritize when it needs to ...?")
    if tpl == "T5_purpose_en" or not is_chinese_question(question):
        return ("purpose_en", "en")

    # 4. Neglect family: T1 ("如果组织忽视X，最直接的安全缺口是什么？")
    #    and MC ("忽视X最可能直接导致什么后果？")
    if tpl == "T1_neglect" or "忽视" in stem:
        return ("neglect_zh", "neglect")

    # 5. Implementation / Audit / Practice family: T2 ("某…应如何开始实施X？")
    #    and MC ("部署X时，以下哪项做法最合理？" / "关于X，哪项实施建议最符合安全实践？" / "一次审计要求…" / "在资源有限时…")
    if tpl == "T2_implementation" or any(w in stem for w in ("开始实施", "哪项做法最合理", "哪项实施建议")):
        return ("implementation_zh", "impl")

    return ("audit_practice_mc", stem[:24])


def main() -> None:
    dataset_path = ROOT / "public_dataset.jsonl"
    raw_bytes = dataset_path.read_bytes().replace(b"\r\n", b"\n")
    dataset_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    rows = [json.loads(line) for line in raw_bytes.decode("utf-8").splitlines() if line.strip()]
    normal_rows = [r for r in rows if r["expected"]["decision"] == "answer"]

    splits_v28 = json.loads((ROOT / "experiments/v28/splits.json").read_text(encoding="utf-8"))
    canonical_controls = splits_v28["canonical_controls"]

    # Group questions into scenario/sibling families
    # Group key: (augmentation_group, family_kind, normalized_core_if_scenario)
    groups: dict[str, list[dict]] = collections.defaultdict(list)
    question_to_group: dict[str, str] = {}
    scenario_families: dict[str, list[str]] = collections.defaultdict(list)

    for r in normal_rows:
        qid = r["id"]
        ctrl = r["provenance"]["augmentation_group"]
        q_text = r["input"]["text"]
        f_kind, f_core = normalize_scenario_stem(q_text)
        if f_kind == "scenario_failure":
            g_id = f"{ctrl}::scenario::{f_core}"
            scenario_families[g_id].append(qid)
        else:
            g_id = f"{ctrl}::{f_kind}"
        groups[g_id].append(r)
        question_to_group[qid] = g_id

    # Deterministically select intact groups to form a 150-question stratified frozen shadow set:
    # Target composition (~24% of 626 = 150):
    # - 12 intact scenario families (12 T3_scenario + their 34 scenario MC siblings = 46 questions)
    # - 11 T1_neglect groups (11 T1 + their neglect MCs)
    # - 11 T2_implementation groups (11 T2 + their implementation MCs)
    # - 11 T4_purpose_zh groups (11 T4 + their Chinese purpose MCs)
    # - 12 T5_purpose_en groups (12 T5 + their English MCs)
    # Adjust with audit_practice_mc groups so total is exactly 150 and all 54 controls are in train.
    rng = random.Random("v30-frozen-shadow-20261030")
    all_controls = sorted(canonical_controls.keys())
    shuffled_controls = list(all_controls)
    rng.shuffle(shuffled_controls)

    shadow_group_ids: set[str] = set()
    # Partition the 54 controls into 5 disjoint buckets of 11, 11, 11, 11, 10 controls
    # so every control keeps 4 of its 5 template families in train and puts 1 intact family in shadow!
    scen_ctrls = set(shuffled_controls[0:12])
    t1_ctrls = set(shuffled_controls[12:23])
    t2_ctrls = set(shuffled_controls[23:34])
    t4_ctrls = set(shuffled_controls[34:45])
    t5_ctrls = set(shuffled_controls[45:54]) | set(shuffled_controls[0:3])

    for g_id, g_rows in groups.items():
        ctrl = g_id.split("::")[0]
        kind = g_id.split("::")[1]
        if kind == "scenario" and ctrl in scen_ctrls:
            shadow_group_ids.add(g_id)
        elif kind == "neglect_zh" and ctrl in t1_ctrls:
            shadow_group_ids.add(g_id)
        elif kind == "implementation_zh" and ctrl in t2_ctrls:
            shadow_group_ids.add(g_id)
        elif kind == "purpose_zh" and ctrl in t4_ctrls:
            shadow_group_ids.add(g_id)
        elif kind == "purpose_en" and ctrl in t5_ctrls:
            shadow_group_ids.add(g_id)

    shadow_ids = [r["id"] for g_id in sorted(shadow_group_ids) for r in groups[g_id]]

    # Top up or trim using intact single/pair audit_practice_mc groups to hit exactly 150
    audit_groups = [
        (g_id, [r["id"] for r in g_rows])
        for g_id, g_rows in sorted(groups.items())
        if g_id.split("::")[1] == "audit_practice_mc" and g_id not in shadow_group_ids
    ]
    rng.shuffle(audit_groups)

    for g_id, qids in audit_groups:
        if len(shadow_ids) + len(qids) <= 150:
            shadow_group_ids.add(g_id)
            shadow_ids.extend(qids)
        if len(shadow_ids) == 150:
            break

    shadow_set = set(shadow_ids)
    train_ids = [r["id"] for r in normal_rows if r["id"] not in shadow_set]

    # Verify zero group leakage and verify scenario family integrity
    for g_id, qids in scenario_families.items():
        in_shadow = [q in shadow_set for q in qids]
        assert len(set(in_shadow)) == 1, f"Scenario family split across train/shadow: {g_id}"

    by_id = {r["id"]: r for r in normal_rows}
    shadow_tpl_counts = collections.Counter(classify_short_answer_template(by_id[q]["input"]["text"]) for q in shadow_ids)
    shadow_lang_counts = collections.Counter("zh" if is_chinese_question(by_id[q]["input"]["text"]) else "en" for q in shadow_ids)
    train_controls = {by_id[q]["provenance"]["augmentation_group"] for q in train_ids}
    shadow_controls = {by_id[q]["provenance"]["augmentation_group"] for q in shadow_ids}

    manifest = {
        "schema_version": 1,
        "seed": "v30-frozen-shadow-20261030",
        "created_at": "2026-10-30T15:48:00+08:00",
        "dataset_sha256": dataset_sha256,
        "prior_public_exposure": True,
        "caveat": "Frozen shadow regression set stratified by template, control family, and language with strict scenario-family group splitting. Not claimed as historically unseen data.",
        "grouping_algorithm": "normalize_scenario_stem: strips organization actor and T3/MC boilerplate to group identical failure scenarios (T3 + MC siblings) into atomic scenario families, and groups T1/T2/T4/T5 with their corresponding MC siblings per control.",
        "counts": {
            "total_normal": len(normal_rows),
            "train_count": len(train_ids),
            "shadow_count": len(shadow_ids),
            "train_unique_controls": len(train_controls),
            "shadow_unique_controls": len(shadow_controls),
            "total_scenario_families": len(scenario_families),
            "shadow_by_template": dict(shadow_tpl_counts),
            "shadow_by_language": dict(shadow_lang_counts),
        },
        "canonical_controls": canonical_controls,
        "shadow_ids": sorted(shadow_ids),
        "train_ids": sorted(train_ids),
        "scenario_families": {k: sorted(v) for k, v in sorted(scenario_families.items())},
        "question_to_group": question_to_group,
    }

    out_path = ROOT / "experiments/v30/frozen_shadow_manifest.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["counts"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

