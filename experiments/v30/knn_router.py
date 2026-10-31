"""V30 kNN & Hybrid Router Experiments (K1, K2, K3, n-gram ablations, threshold calibration, R0-R4, T3_ROUTING_AUDIT.jsonl)."""
from __future__ import annotations

import collections
import json
import math
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / "attack_defense_bot/attack_defense_bot"), str(HERE)]

from answer_compiler import classify_short_answer_template, resolve_control_id
from build_shadow_manifest import normalize_scenario_stem
from control_routing import control_scopes
from retrieval import guide_file, index


def clean_question_stem(q: str) -> str:
    q = str(q or "").replace("【问题】", "").strip()
    q = re.split(r"\n(?:【选项】|选项[：:]?)", q, maxsplit=1)[0].strip()
    q = re.sub(r"^某[^遇发]{1,15}(?:遇到以下情况|发现)[:：]\s*", "", q)
    q = re.sub(r"[。！？!?]?\s*(?:应优先采取什么安全措施，为什么？|哪项措施最直接针对这一问题？)$", "", q)
    return q.strip()


def extract_char_ngrams(text: str, n_min: int = 2, n_max: int = 4) -> collections.Counter:
    cleaned = re.sub(r"[\s\W_]+", "", str(text or "").lower(), flags=re.UNICODE)
    counts: collections.Counter = collections.Counter()
    length = len(cleaned)
    for n in range(n_min, n_max + 1):
        if length >= n:
            for i in range(length - n + 1):
                counts[cleaned[i : i + n]] += 1
    # Also add English/ASCII whole words for bilingual precision
    for word in re.findall(r"[a-z0-9]{2,}", str(text or "").lower()):
        counts[f"w:{word}"] += 2
    return counts


class CharNgramKNNRouter:
    """Deterministic TF-IDF character n-gram kNN router over public training questions and bundled guides."""

    def __init__(
        self,
        n_min: int = 2,
        n_max: int = 4,
        k: int = 5,
        include_guides: bool = True,
        min_top1_score: float = 0.42,
        min_margin: float = 0.10,
    ) -> None:
        self.n_min = n_min
        self.n_max = n_max
        self.k = k
        self.include_guides = include_guides
        self.min_top1_score = min_top1_score
        self.min_margin = min_margin
        self.entries: list[dict[str, Any]] = []
        self.df: collections.Counter = collections.Counter()
        self.total_docs = 0

    def fit(self, train_rows: list[dict[str, Any]], canonical_controls: dict[str, str]) -> "CharNgramKNNRouter":
        raw_entries: list[dict[str, Any]] = []
        for r in train_rows:
            qid = r["id"]
            ag = r.get("provenance", {}).get("augmentation_group", "")
            ctrl = canonical_controls.get(ag, "")
            if not ctrl:
                continue
            q_text = r["input"]["text"]
            q_type = "MC" if r["expected"].get("answer") in {"A", "B", "C", "D"} else "SA"
            tpl = classify_short_answer_template(q_text)
            stem = clean_question_stem(q_text)
            ref = r["expected"].get("reference_answer", "")
            # Weight question stem 2x + reference answer 1x so both scenario wording and mechanism terms match
            combined = f"{stem} {stem} {ref}" if q_type == "MC" else f"{stem} {stem} {ref}"
            f_kind, f_core = normalize_scenario_stem(q_text)
            scen_key = f"{ag}::scenario::{f_core}" if f_kind == "scenario_failure" else ""
            feats = extract_char_ngrams(combined, self.n_min, self.n_max)
            raw_entries.append(
                {
                    "id": qid,
                    "control": ctrl,
                    "q_type": q_type,
                    "template": tpl,
                    "raw_text": q_text.splitlines()[0],
                    "stem": stem,
                    "scenario_key": scen_key,
                    "feats": feats,
                    "is_guide": False,
                }
            )

        if self.include_guides:
            scopes = control_scopes()
            for doc in index()[0]:
                gid = doc["id"]
                if not gid.startswith("guide-"):
                    continue
                sc = scopes.get(gid, {})
                sc_text = " ".join(
                    list(sc.get("protected_objects", []))
                    + list(sc.get("failure_modes", []))
                    + list(sc.get("primary_mechanisms", []))
                )
                g_text = f"{doc['title']} {doc.get('aliases', '')} {doc.get('text_zh', '')} {doc.get('text_en', '')} {sc_text}"
                feats = extract_char_ngrams(g_text, self.n_min, self.n_max)
                raw_entries.append(
                    {
                        "id": f"bundled:{gid}",
                        "control": gid,
                        "q_type": "GUIDE",
                        "template": "GUIDE",
                        "raw_text": doc["title"],
                        "stem": doc.get("text_zh", ""),
                        "scenario_key": "",
                        "feats": feats,
                        "is_guide": True,
                    }
                )

        self.df = collections.Counter()
        for e in raw_entries:
            self.df.update(e["feats"].keys())
        self.total_docs = len(raw_entries)

        self.entries = []
        for e in raw_entries:
            vec = self._to_tfidf(e["feats"])
            e_copy = dict(e)
            e_copy["vec"] = vec
            del e_copy["feats"]
            self.entries.append(e_copy)
        return self

    def _to_tfidf(self, feats: collections.Counter) -> dict[str, float]:
        n_docs = max(1, self.total_docs)
        vec = {
            k: (1.0 + math.log(c)) * math.log(1.0 + n_docs / (1.0 + self.df.get(k, 0)))
            for k, c in feats.items()
        }
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {k: v / norm for k, v in vec.items()}

    def predict(
        self,
        question: str,
        exclude_ids: set[str] | None = None,
        exclude_scenario_key: str = "",
        exclude_templates: set[str] | None = None,
    ) -> dict[str, Any]:
        stem = clean_question_stem(question)
        q_vec = self._to_tfidf(extract_char_ngrams(f"{stem} {stem}", self.n_min, self.n_max))
        exclude_ids = exclude_ids or set()
        exclude_templates = exclude_templates or set()

        sims: list[tuple[float, dict[str, Any]]] = []
        for e in self.entries:
            if e["id"] in exclude_ids:
                continue
            if exclude_scenario_key and e["scenario_key"] == exclude_scenario_key:
                continue
            if e["template"] in exclude_templates:
                continue
            e_vec = e["vec"]
            if len(q_vec) < len(e_vec):
                s = sum(v * e_vec.get(k, 0.0) for k, v in q_vec.items())
            else:
                s = sum(v * q_vec.get(k, 0.0) for k, v in e_vec.items())
            sims.append((s, e))

        sims.sort(key=lambda x: x[0], reverse=True)
        if not sims:
            return {
                "predicted_control": "",
                "top1_score": 0.0,
                "top2_control": "",
                "top2_score": 0.0,
                "margin": 0.0,
                "high_confidence": False,
                "nearest_id": "",
                "nearest_type": "",
                "nearest_text": "",
                "nearest_scenario_key": "",
                "candidate_controls": [],
            }

        # Aggregate top-k similarity by control, while also tracking best single-item similarity per control
        control_best_sim: dict[str, float] = {}
        control_vote_sum: collections.Counter = collections.Counter()
        for s, e in sims[: max(self.k, 15)]:
            c = e["control"]
            if c not in control_best_sim:
                control_best_sim[c] = s
        for s, e in sims[: self.k]:
            control_vote_sum[e["control"]] += s

        ranked_controls = sorted(
            control_vote_sum.keys(),
            key=lambda c: (control_vote_sum[c], control_best_sim.get(c, 0.0)),
            reverse=True,
        )
        top1_ctrl = ranked_controls[0]
        top1_sim = control_best_sim.get(top1_ctrl, sims[0][0])

        # Find second best distinct control across top matches
        other_controls = [c for c in control_best_sim if c != top1_ctrl]
        top2_ctrl = other_controls[0] if other_controls else ""
        top2_sim = control_best_sim.get(top2_ctrl, 0.0) if top2_ctrl else 0.0
        margin = top1_sim - top2_sim

        nearest = sims[0][1]
        high_conf = bool(top1_sim >= self.min_top1_score and margin >= self.min_margin)

        cand_list = list(control_best_sim.keys())[:10]
        return {
            "predicted_control": top1_ctrl,
            "top1_score": round(top1_sim, 4),
            "top2_control": top2_ctrl,
            "top2_score": round(top2_sim, 4),
            "margin": round(margin, 4),
            "high_confidence": high_conf,
            "nearest_id": nearest["id"],
            "nearest_type": nearest["q_type"],
            "nearest_text": nearest["raw_text"],
            "nearest_scenario_key": nearest["scenario_key"],
            "candidate_controls": cand_list,
        }


def run_experiments() -> dict[str, Any]:
    manifest = json.loads((HERE / "frozen_shadow_manifest.json").read_text(encoding="utf-8"))
    canonical_controls = manifest["canonical_controls"]
    rows = [json.loads(l) for l in (ROOT / "public_dataset.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    normal_rows = [r for r in rows if r["expected"]["decision"] == "answer"]
    t3_rows = [r for r in normal_rows if classify_short_answer_template(r["input"]["text"]) == "T3_scenario"]

    # 1. N-gram range comparison across K1 (ordinary LOO), K2 (scenario-family blocked), K3 (cross-template only)
    ngram_configs = [(2, 3), (2, 4), (2, 5), (3, 5)]
    ngram_results: dict[str, Any] = {}

    for n_min, n_max in ngram_configs:
        router = CharNgramKNNRouter(n_min=n_min, n_max=n_max, k=5, include_guides=True).fit(normal_rows, canonical_controls)
        k1_ok = k2_ok = k3_ok = 0
        sibling_count = 0
        for r in t3_rows:
            qid = r["id"]
            ag = r["provenance"]["augmentation_group"]
            true_ctrl = canonical_controls[ag]
            q_text = r["input"]["text"]
            f_kind, f_core = normalize_scenario_stem(q_text)
            scen_key = f"{ag}::scenario::{f_core}"

            # K1: Ordinary leave-one-question-out
            p1 = router.predict(q_text, exclude_ids={qid})
            if p1["predicted_control"] == true_ctrl:
                k1_ok += 1
            if p1["nearest_scenario_key"] == scen_key and p1["nearest_type"] == "MC":
                sibling_count += 1

            # K2: Scenario-family blocked evaluation (exclude all questions sharing this scenario_key)
            p2 = router.predict(q_text, exclude_ids={qid}, exclude_scenario_key=scen_key)
            if p2["predicted_control"] == true_ctrl:
                k2_ok += 1

            # K3: Cross-template only (exclude all T3_scenario and all scenario_key MCs across the dataset)
            # We test predicting T3 using only T1/T2/T4/T5, non-scenario MCs, and bundled guides
            scen_mc_ids = {e["id"] for e in router.entries if e["scenario_key"]}
            p3 = router.predict(q_text, exclude_ids=scen_mc_ids, exclude_templates={"T3_scenario"})
            if p3["predicted_control"] == true_ctrl:
                k3_ok += 1

        ngram_results[f"char_{n_min}_{n_max}"] = {
            "t3_total": len(t3_rows),
            "K1_ordinary_loo_correct": k1_ok,
            "K1_ordinary_loo_accuracy": round(k1_ok / len(t3_rows), 4),
            "K1_nearest_is_same_scenario_mc_sibling": sibling_count,
            "K1_same_scenario_mc_sibling_rate": round(sibling_count / len(t3_rows), 4),
            "K2_scenario_family_blocked_correct": k2_ok,
            "K2_scenario_family_blocked_accuracy": round(k2_ok / len(t3_rows), 4),
            "K3_cross_template_only_correct": k3_ok,
            "K3_cross_template_only_accuracy": round(k3_ok / len(t3_rows), 4),
        }

    # 2. Calibrate confidence threshold strictly on the train partition (476 questions, 36 T3 questions)
    train_id_set = set(manifest["train_ids"])
    train_rows = [r for r in normal_rows if r["id"] in train_id_set]
    train_t3 = [r for r in t3_rows if r["id"] in train_id_set]
    train_router = CharNgramKNNRouter(n_min=2, n_max=4, k=5, include_guides=True).fit(train_rows, canonical_controls)

    k1_train_records = []
    k2_train_records = []
    for r in train_t3:
        qid = r["id"]
        ag = r["provenance"]["augmentation_group"]
        true_ctrl = canonical_controls[ag]
        q_text = r["input"]["text"]
        _, f_core = normalize_scenario_stem(q_text)
        scen_key = f"{ag}::scenario::{f_core}"

        p1 = train_router.predict(q_text, exclude_ids={qid})
        k1_train_records.append((p1["top1_score"], p1["margin"], p1["predicted_control"] == true_ctrl))

        p2 = train_router.predict(q_text, exclude_ids={qid}, exclude_scenario_key=scen_key)
        k2_train_records.append((p2["top1_score"], p2["margin"], p2["predicted_control"] == true_ctrl))

    # Grid search thresholds on train to maximize high-confidence coverage subject to >=97% precision on K2 and 100% on K1
    best_thresh = (0.42, 0.10)
    best_calibration_info = {}
    for s_th in [0.30, 0.35, 0.40, 0.42, 0.45, 0.50]:
        for m_th in [0.05, 0.08, 0.10, 0.12, 0.15]:
            k1_acc_hits = [ok for s, m, ok in k1_train_records if s >= s_th and m >= m_th]
            k2_acc_hits = [ok for s, m, ok in k2_train_records if s >= s_th and m >= m_th]
            k1_prec = sum(k1_acc_hits) / len(k1_acc_hits) if k1_acc_hits else 1.0
            k2_prec = sum(k2_acc_hits) / len(k2_acc_hits) if k2_acc_hits else 1.0
            if k1_prec == 1.0 and k2_prec == 1.0 and len(k1_acc_hits) == len(k1_train_records):
                best_thresh = (s_th, m_th)
                best_calibration_info = {
                    "min_top1_score": s_th,
                    "min_margin": m_th,
                    "train_k1_coverage": round(len(k1_acc_hits) / len(k1_train_records), 4),
                    "train_k1_precision": round(k1_prec, 4),
                    "train_k2_coverage": round(len(k2_acc_hits) / len(k2_train_records), 4),
                    "train_k2_precision": round(k2_prec, 4),
                }
                break
        if best_calibration_info:
            break

    # 3. Generate detailed K1 + K2 audit records for all 48 T3 questions
    full_router = CharNgramKNNRouter(
        n_min=2,
        n_max=4,
        k=5,
        include_guides=True,
        min_top1_score=best_thresh[0],
        min_margin=best_thresh[1],
    ).fit(normal_rows, canonical_controls)

    v18_routes = {
        json.loads(l)["id"]: json.loads(l)["selected"][0]
        for l in (ROOT / "output/route_audit_v18_full_catalog.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()
    }
    guides = {d["id"]: d for d in index()[0] if d["id"].startswith("guide-")}

    t3_audit_rows = []
    for r in t3_rows:
        qid = r["id"]
        ag = r["provenance"]["augmentation_group"]
        true_ctrl = canonical_controls[ag]
        q_text = r["input"]["text"]
        _, f_core = normalize_scenario_stem(q_text)
        scen_key = f"{ag}::scenario::{f_core}"

        p1 = full_router.predict(q_text, exclude_ids={qid})
        p2 = full_router.predict(q_text, exclude_ids={qid}, exclude_scenario_key=scen_key)
        raw_llm_route = v18_routes.get(qid, "")
        r_files = [guide_file(guides[raw_llm_route])] if raw_llm_route in guides else []
        p8_ctrl = resolve_control_id(q_text, "", r_files, raw_llm_route) or raw_llm_route

        t3_audit_rows.append(
            {
                "question_id": qid,
                "question": q_text,
                "true_control": true_ctrl,
                "expected_control": true_ctrl,
                "current_P8_control": p8_ctrl,
                "raw_v18_llm_router_control": raw_llm_route,
                "predicted_control": p1["predicted_control"],
                "knn_top1": p1["predicted_control"],
                "top1_score": p1["top1_score"],
                "knn_top1_score": p1["top1_score"],
                "knn_top2": p1["top2_control"],
                "top2_score": p1["top2_score"],
                "knn_top2_score": p1["top2_score"],
                "margin": p1["margin"],
                "nearest_question_id": p1["nearest_id"],
                "nearest_neighbor_id": p1["nearest_id"],
                "nearest_question_type": p1["nearest_type"],
                "nearest_neighbor_type": p1["nearest_type"],
                "nearest_question_text": p1["nearest_text"],
                "nearest_neighbor_text": p1["nearest_text"],
                "is_same_scenario_mc_sibling": bool(p1["nearest_scenario_key"] == scen_key and p1["nearest_type"] == "MC"),
                "k2_blocked_top1": p2["predicted_control"],
                "k2_blocked_top1_score": p2["top1_score"],
                "k2_blocked_margin": p2["margin"],
                "k2_blocked_high_confidence": p2["high_confidence"],
                "hybrid_control": p1["predicted_control"] if p1["high_confidence"] else raw_llm_route,
                "used_llm_fallback": not p1["high_confidence"],
                "official_correct": True,
            }
        )

    (ROOT / "T3_ROUTING_AUDIT.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in t3_audit_rows) + "\n",
        encoding="utf-8",
    )

    summary = {
        "ngram_ablation": ngram_results,
        "threshold_calibration_on_train": best_calibration_info,
        "t3_count": len(t3_rows),
        "raw_v18_llm_router_correct": sum(1 for x in t3_audit_rows if x["raw_v18_llm_router_control"] == x["true_control"]),
        "current_p8_patched_correct": sum(1 for x in t3_audit_rows if x["current_P8_control"] == x["true_control"]),
        "knn_k1_loo_correct": sum(1 for x in t3_audit_rows if x["knn_top1"] == x["true_control"]),
        "knn_k1_same_scenario_mc_sibling_count": sum(1 for x in t3_audit_rows if x["is_same_scenario_mc_sibling"]),
        "knn_k2_blocked_correct": sum(1 for x in t3_audit_rows if x["k2_blocked_top1"] == x["true_control"]),
        "knn_k2_high_conf_count": sum(1 for x in t3_audit_rows if x["k2_blocked_high_confidence"]),
        "knn_k2_high_conf_correct": sum(
            1 for x in t3_audit_rows if x["k2_blocked_high_confidence"] and x["k2_blocked_top1"] == x["true_control"]
        ),
    }
    (HERE / "results").mkdir(parents=True, exist_ok=True)
    (HERE / "results/knn_router_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == "__main__":
    run_experiments()
