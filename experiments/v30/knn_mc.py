"""V30 Deterministic kNN Multiple-Choice API-Failure-Only Fallback (Section 11) and MC_FALLBACK_AUDIT.jsonl."""
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

from answer_compiler import resolve_control_id
from build_shadow_manifest import normalize_scenario_stem
from control_routing import control_scopes
from retrieval import index


NEGATIVE_STEM_RE = re.compile(
    r"(?:不合理|不正确|不属于|不符合|不恰当|错误的是|最不|不应|哪项不是|不应优先|least\s+appropriate|not\s+appropriate|incorrect|except)",
    re.I,
)


def parse_mc_question(question: str) -> tuple[str, dict[str, str]]:
    q = str(question or "").replace("【问题】", "").strip()
    opts = dict(re.findall(r"^\s*([ABCD])[.．、:：)\]]\s*(.+)$", q, re.M))
    stem = re.split(r"\n", q, maxsplit=1)[0].strip()
    return stem, opts


def char_ngrams(text: str, n_min: int = 2, n_max: int = 3) -> collections.Counter:
    cleaned = re.sub(r"\s+", "", str(text or "").lower())
    c: collections.Counter = collections.Counter()
    length = len(cleaned)
    for n in range(n_min, n_max + 1):
        if length >= n:
            for i in range(length - n + 1):
                c[cleaned[i : i + n]] += 1
    for w in re.findall(r"[a-z0-9]{2,}", str(text or "").lower()):
        c[f"w:{w}"] += 2
    return c


class KNNMultipleChoiceFallback:
    """API-failure-only deterministic MC fallback trained on public normal questions + bundled guides."""

    def __init__(self, k: int = 7, include_guides: bool = True) -> None:
        self.k = k
        self.include_guides = include_guides
        self.items: list[dict[str, Any]] = []
        self.df: collections.Counter = collections.Counter()
        self.total_docs = 0
        self.guide_vecs: dict[str, dict[str, float]] = {}

    def fit(self, train_rows: list[dict[str, Any]], canonical_controls: dict[str, str] | None = None) -> "KNNMultipleChoiceFallback":
        canonical_controls = canonical_controls or {}
        raw_items = []
        for r in train_rows:
            if r["expected"]["decision"] != "answer":
                continue
            qid = r["id"]
            ag = r.get("provenance", {}).get("augmentation_group", "")
            ctrl = canonical_controls.get(ag, ag)
            q_text = r["input"]["text"]
            stem, opts = parse_mc_question(q_text)
            ref = r["expected"].get("reference_answer", "")
            f_kind, f_core = normalize_scenario_stem(q_text)
            group_key = f"{ag}::scenario::{f_core}" if f_kind == "scenario_failure" else f"{ag}::{f_kind}"
            raw_items.append(
                {
                    "id": qid,
                    "group": ag,
                    "control": ctrl,
                    "group_key": group_key,
                    "stem": stem,
                    "opts": opts,
                    "ans": r["expected"].get("answer", ""),
                    "ref": ref,
                    "mc": bool(opts),
                }
            )

        self.df = collections.Counter()
        for it in raw_items:
            self.df.update(char_ngrams(it["stem"] + " " + it["ref"]).keys())

        guides = {doc["id"]: doc for doc in index()[0] if doc["id"].startswith("guide-")}
        if self.include_guides:
            for gid, gdoc in guides.items():
                self.df.update(char_ngrams(gdoc.get("title", "") + " " + gdoc.get("text", "")).keys())

        self.total_docs = len(raw_items) + (len(guides) if self.include_guides else 0)

        self.items = []
        for it in raw_items:
            it_copy = dict(it)
            it_copy["sv"] = self._vec(it["stem"])
            it_copy["rv"] = self._vec(it["stem"] + " " + it["ref"])
            self.items.append(it_copy)

        self.guide_vecs = {}
        self.control_to_group = {}
        if canonical_controls:
            for ag, cid in canonical_controls.items():
                self.control_to_group[cid] = ag
        scopes = control_scopes()
        if self.include_guides:
            for gid, gdoc in guides.items():
                sc = scopes.get(gid, {})
                sc_txt = " ".join(
                    list(sc.get("protected_objects", []))
                    + list(sc.get("failure_modes", []))
                    + list(sc.get("primary_mechanisms", []))
                )
                g_txt = f"{gdoc.get('title', '')} {gdoc.get('aliases', '')} {gdoc.get('text_zh', '')} {gdoc.get('text_en', '')} {sc_txt}"
                self.guide_vecs[gid] = self._vec(g_txt)

        return self

    def _vec(self, text: str) -> dict[str, float]:
        f = char_ngrams(text)
        n_docs = max(1, self.total_docs)
        v = {k: (1.0 + math.log(c)) * math.log(1.0 + n_docs / (1.0 + self.df.get(k, 0))) for k, c in f.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {k: x / norm for k, x in v.items()}

    @staticmethod
    def _cos(a: dict[str, float], b: dict[str, float]) -> float:
        if len(a) > len(b):
            a, b = b, a
        return sum(x * b.get(k, 0.0) for k, x in a.items())

    def predict(
        self,
        question: str,
        exclude_ids: set[str] | None = None,
        exclude_group_key: str = "",
        context_text: str = "",
    ) -> dict[str, Any]:
        stem, opts = parse_mc_question(question)
        if not opts:
            return {"choice": "A", "confidence": 0.0, "margin": 0.0, "predicted_group": "", "predicted_control": "", "scores": {}}

        exclude_ids = exclude_ids or set()
        sv = self._vec(stem + (" " + context_text if context_text else ""))

        others = [
            o
            for o in self.items
            if o["id"] not in exclude_ids and (not exclude_group_key or o["group_key"] != exclude_group_key)
        ]
        profiles = self.guide_vecs

        # Step 1: Check if options themselves name specific controls (Type 1 MC: "Which control matches...")
        opt_controls: dict[str, str] = {}
        for letter, opt_text in opts.items():
            cleaned_opt = re.sub(r"^有关(.+?)的通用控制描述[。.]?$", r"\1", opt_text.strip())
            cid = resolve_control_id(cleaned_opt)
            if cid and cid.startswith("guide-"):
                opt_controls[letter] = cid

        # Step 2: Resolve stem control via explicit control name first, else kNN + guide profile similarity
        explicit_stem_ctrl = resolve_control_id(stem)
        sims = sorted(((self._cos(sv, o["rv"]), o["group"], o["control"]) for o in others), reverse=True)[: self.k]
        votes: collections.Counter = collections.Counter()
        ctrl_votes: collections.Counter = collections.Counter()
        for s, g, ctrl in sims:
            votes[g] += s
            if ctrl:
                ctrl_votes[ctrl] += s
        if profiles:
            for cid, pvec in profiles.items():
                ctrl_votes[cid] += 0.8 * self._cos(sv, pvec)

        if explicit_stem_ctrl and explicit_stem_ctrl.startswith("guide-"):
            pred_ctrl = explicit_stem_ctrl
            pred_group = self.control_to_group.get(pred_ctrl, votes.most_common(1)[0][0] if votes else "")
        else:
            pred_ctrl = ctrl_votes.most_common(1)[0][0] if ctrl_votes else ""
            pred_group = self.control_to_group.get(pred_ctrl, votes.most_common(1)[0][0] if votes else "")

        # Step 3: Score options
        scores: dict[str, float] = {}
        group_refs = " ".join(o["ref"] for o in others if o["group"] == pred_group)
        if len(opt_controls) >= 3 and profiles:
            # Type 1 MC: Each option is a control name -> score each option's control profile against the question stem + kNN votes
            for letter, opt_text in opts.items():
                cid = opt_controls.get(letter, "")
                if cid and cid in profiles:
                    s_prof = self._cos(sv, profiles[cid]) + 0.45 * ctrl_votes.get(cid, 0.0)
                    if "通用控制描述" in opt_text:
                        s_prof -= 0.5
                    scores[letter] = round(s_prof, 4)
                else:
                    scores[letter] = round(self._cos(self._vec(opt_text), sv), 4)
        else:
            # Type 2 MC: Options are mechanism/practice/evidence descriptions -> score against pred_ctrl guide + training refs
            guide_txt = ""
            if self.include_guides and pred_ctrl:
                guides = {doc["id"]: doc for doc in index()[0] if doc["id"].startswith("guide-")}
                gdoc = guides.get(pred_ctrl, {})
                guide_txt = f"{gdoc.get('title', '')} {gdoc.get('text_zh', '')} {gdoc.get('text_en', '')}"
            target_vec = self._vec(f"{group_refs} {guide_txt} {guide_txt}")
            for letter, opt_text in opts.items():
                ovec = self._vec(opt_text)
                sim_target = self._cos(ovec, target_vec)
                if "通用控制描述" in opt_text:
                    sim_target -= 0.5
                scores[letter] = round(sim_target, 4)

        is_neg = bool(NEGATIVE_STEM_RE.search(stem))
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=not is_neg)
        best_letter, best_score = ranked[0]
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0
        margin = round(abs(best_score - second_score), 4)

        return {
            "choice": best_letter,
            "confidence": round(best_score, 4),
            "margin": margin,
            "predicted_group": pred_group,
            "predicted_control": pred_ctrl,
            "scores": scores,
        }


def run_mc_experiments() -> dict[str, Any]:
    manifest = json.loads((HERE / "frozen_shadow_manifest.json").read_text(encoding="utf-8"))
    canonical_controls = manifest["canonical_controls"]
    rows = [json.loads(l) for l in (ROOT / "public_dataset.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    normal_rows = [r for r in rows if r["expected"]["decision"] == "answer"]
    mc_rows = [r for r in normal_rows if r["expected"].get("answer") in {"A", "B", "C", "D"}]

    # 1. Reproduce Astra's exact baseline LOO (include_guides=False, no negative flip)
    astra_model = KNNMultipleChoiceFallback(k=7, include_guides=False).fit(normal_rows, canonical_controls)
    astra_loo_ok = 0
    for it in astra_model.items:
        if not it["mc"]:
            continue
        others = [o for o in astra_model.items if o["id"] != it["id"]]
        sims = sorted(((astra_model._cos(it["sv"], o["rv"]), o["group"]) for o in others), reverse=True)[:7]
        votes: collections.Counter = collections.Counter()
        for s, g in sims:
            votes[g] += s
        g = votes.most_common(1)[0][0]
        profile = astra_model._vec(" ".join(o["ref"] for o in others if o["group"] == g))
        scores = {L: astra_model._cos(astra_model._vec(t), profile) for L, t in it["opts"].items()}
        pred = max(scores, key=scores.get)
        if pred == it["ans"]:
            astra_loo_ok += 1

    # 2. Evaluate V30 enhanced KNNMultipleChoiceFallback under:
    #    (a) Ordinary leave-one-question-out (LOO)
    #    (b) Near-duplicate sibling-group blocked evaluation
    #    (c) Train-only fit evaluated on Frozen Shadow 101 MCs
    v30_model = KNNMultipleChoiceFallback(k=7, include_guides=True).fit(normal_rows, canonical_controls)
    loo_ok = 0
    loo_route_ok = 0
    blocked_ok = 0
    blocked_route_ok = 0
    margins_loo = []
    margins_blocked = []
    audit_records = []

    for r in mc_rows:
        qid = r["id"]
        ag = r["provenance"]["augmentation_group"]
        true_ctrl = canonical_controls[ag]
        q_text = r["input"]["text"]
        gold = r["expected"]["answer"]
        f_kind, f_core = normalize_scenario_stem(q_text)
        g_key = f"{ag}::scenario::{f_core}" if f_kind == "scenario_failure" else f"{ag}::{f_kind}"

        p_loo = v30_model.predict(q_text, exclude_ids={qid})
        p_blk = v30_model.predict(q_text, exclude_ids={qid}, exclude_group_key=g_key)

        if p_loo["choice"] == gold:
            loo_ok += 1
        if p_loo["predicted_group"] == ag:
            loo_route_ok += 1
        margins_loo.append(p_loo["margin"])

        if p_blk["choice"] == gold:
            blocked_ok += 1
        if p_blk["predicted_group"] == ag:
            blocked_route_ok += 1
        margins_blocked.append(p_blk["margin"])

        audit_records.append(
            {
                "question_id": qid,
                "expected_answer": gold,
                "expected_control": true_ctrl,
                "loo_predicted_choice": p_loo["choice"],
                "loo_correct": p_loo["choice"] == gold,
                "loo_predicted_control": p_loo["predicted_control"],
                "loo_confidence": p_loo["confidence"],
                "loo_margin": p_loo["margin"],
                "group_blocked_predicted_choice": p_blk["choice"],
                "group_blocked_correct": p_blk["choice"] == gold,
                "group_blocked_predicted_control": p_blk["predicted_control"],
                "group_blocked_confidence": p_blk["confidence"],
                "group_blocked_margin": p_blk["margin"],
            }
        )

    # Train-only fit evaluated on Frozen Shadow MCs
    train_set = set(manifest["train_ids"])
    shadow_set = set(manifest["shadow_ids"])
    train_rows = [r for r in normal_rows if r["id"] in train_set]
    shadow_mc_rows = [r for r in mc_rows if r["id"] in shadow_set]
    train_mc_model = KNNMultipleChoiceFallback(k=7, include_guides=True).fit(train_rows, canonical_controls)
    shadow_fb_ok = 0
    for r in shadow_mc_rows:
        p = train_mc_model.predict(r["input"]["text"])
        if p["choice"] == r["expected"]["answer"]:
            shadow_fb_ok += 1

    (ROOT / "MC_FALLBACK_AUDIT.jsonl").write_text(
        "\n".join(json.dumps(rec, ensure_ascii=False) for rec in audit_records) + "\n",
        encoding="utf-8",
    )

    summary = {
        "mc_total": len(mc_rows),
        "astra_baseline_loo_correct": astra_loo_ok,
        "astra_baseline_loo_accuracy": round(astra_loo_ok / len(mc_rows), 4),
        "v30_ordinary_loo_correct": loo_ok,
        "v30_ordinary_loo_accuracy": round(loo_ok / len(mc_rows), 4),
        "v30_ordinary_loo_control_route_accuracy": round(loo_route_ok / len(mc_rows), 4),
        "v30_ordinary_loo_mean_margin": round(sum(margins_loo) / len(margins_loo), 4),
        "v30_group_blocked_correct": blocked_ok,
        "v30_group_blocked_accuracy": round(blocked_ok / len(mc_rows), 4),
        "v30_group_blocked_control_route_accuracy": round(blocked_route_ok / len(mc_rows), 4),
        "v30_group_blocked_mean_margin": round(sum(margins_blocked) / len(margins_blocked), 4),
        "v30_frozen_shadow_mc_total": len(shadow_mc_rows),
        "v30_frozen_shadow_mc_fallback_correct": shadow_fb_ok,
        "v30_frozen_shadow_mc_fallback_accuracy": round(shadow_fb_ok / len(shadow_mc_rows), 4),
        "coverage": 1.0,
    }
    (HERE / "results").mkdir(parents=True, exist_ok=True)
    (HERE / "results/knn_mc_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == "__main__":
    run_mc_experiments()
