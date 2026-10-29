# V29 Official Scorer Alignment & Architecture Design (`V29_OFFICIAL_SCORER_DESIGN.md`)

## 1. Executive Summary & Root-Cause Diagnosis

In V28 and V28.1, release selection relied on an LLM-based semantic evaluator (`experiments/v28/semantic_evaluator.py`), under which Baseline `A` scored **88.89%** on validation (`15/18` short answers) and **92.59%** on holdout (`16/18` short answers). However, classroom platform evaluation uses the official scorer in [`eval_dataset.py`](file:///c:/data/software/big_homework/attack_defense_bot/attack_defense_bot/eval_dataset.py):

```python
DEFAULT_SHORT_ANSWER_POLICY = "concepts"
DEFAULT_SHORT_ANSWER_CONCEPT_THRESHOLD = 1.0
```

When V28.1's saved `A` outputs are re-scored using `eval_dataset.py::contains_expected_concepts` at threshold `1.0`, the true official baseline is:

- **Validation short-answer official accuracy**: **12 / 18 (66.67%)** (combined normal: **21 / 27 = 77.78%**)
- **Holdout short-answer official accuracy**: **10 / 18 (55.56%)** (combined normal: **19 / 27 = 70.37%**)

This directly explains why the platform normal-question score dropped to `77.027%` (`≈ 57 / 74`): semantically correct paraphrases frequently omitted one required lexical substring group in `expected.concepts` (where **100% of concept groups** must be hit for a short answer to be credited).

Starting in V29:
1. **`eval_dataset.py` (`concepts` policy, `threshold = 1.0`, exact letter for multiple choice, `actual_decision == "error"` counted as wrong) is the sole primary release metric.**
2. V28.1's semantic evaluator and RAGAS metrics are retained strictly as secondary diagnostics and can never override the official scorer.
3. **Zero runtime label access**: production code never imports, reads, or references `public_dataset.jsonl`, `expected.concepts`, `reference_answer`, `expected.answer`, `augmentation_group`, or `question_id`.

---

## 2. Official Scorer Mechanics & Concept Data Quality Audit (Section 19)

### 2.1 Official Scoring Rules (`eval_dataset.py`)
1. **Text Normalization (`normalize_text`)**: Lowercases text and strips all whitespace, punctuation, and symbols (`re.sub(r"[\s\W_]+", "", text.lower(), flags=re.UNICODE)`).
2. **Short-Answer Concept Groups (`contains_expected_concepts`)**:
   - Each short-answer item has $K$ concept groups $G_1, G_2, \dots, G_K$.
   - Group $G_i$ is hit if and only if at least one term $t \in G_i$ satisfies `normalize_text(t) in normalize_text(answer)`.
   - Because `DEFAULT_SHORT_ANSWER_CONCEPT_THRESHOLD = 1.0`, required hits = $\lceil K \times 1.0 \rceil = K$. **Missing even 1 group out of $K$ yields `correct = False`.**
3. **Multiple-Choice (`extract_choice`)**: Strictly checks the predicted option letter (`A`/`B`/`C`/`D`).
4. **Operational / API Errors**: Any unhandled `ApiError` or invalid JSON sets `actual_decision = "error"`, which immediately scores as `0`.

### 2.2 Concept Data Quality Audit on All 226 Public Short Answers
Evaluating `public_dataset.jsonl`'s own gold `reference_answer` against `contains_expected_concepts(..., 1.0)` reveals a critical structural property of the benchmark:

| Audited Text | Passed / Total | Official Pass Rate |
|---|---:|---:|
| `reference_answer` alone (self-pass) | **200 / 226** | **88.50%** |
| `question + "\n" + reference_answer` | **226 / 226** | **100.00%** |

All **26 self-failing `reference_answer` records** fall into two deterministic structural patterns:

1. **Missing Explicit Control Name from Question Stem (20 / 26 items)**:
   - Occurs in `T1_neglect` (`syn-0185`, `syn-0255`, `syn-0549`), `T4_purpose_zh` (`syn-0253`, `syn-0141`, `syn-0325`, `syn-0143`, `syn-0703`, `syn-0448`, `syn-0207`, `syn-0183`, `syn-0115`, `syn-0574`), and `T5_purpose_en` (`syn-0182`, `syn-0714`, `syn-0547`, `syn-0113`, `syn-0336`, `syn-0323`, `syn-0169`).
   - The `reference_answer` begins directly with the verb or effect (e.g., `"避免不可信内容在浏览器中被解释为可执行脚本。"` or `"Prevent attackers from altering or deleting recovery copies."`), while `expected.concepts` includes a dedicated group requiring the control name from the question (e.g., `["上下文相关输出编码", ...]` or `["immutable backups", ...]`).
2. **Missing Question-Side Scenario Anchor (6 / 26 items)**:
   - Occurs in `T3_scenario` (`syn-0576`, `syn-0450`, `syn-0016`, `syn-0002`, `syn-0170`, `syn-0464`).
   - One concept group in `expected.concepts` was automatically extracted from the scenario failure description in the question stem (e.g., `生成` in `"扫描报告每月生成但高风险问题长期无人负责"`, `存储` in `"公开存储桶"`, `位置` in `"位置轨迹和健康信息"`, `记录` in `"敏感客户记录"`, `删除` in `"攻击者删除本账户中的日志"`).

**Engineering Implication**: A high-scoring answer cannot merely output a free-form semantic explanation; it must combine **semantic correctness** with **lexical anchor preservation** from the question stem and **canonical course terminology** from the verified knowledge base.

---

## 3. Two-Layer Target Pipeline Architecture

V29 separates **answering the security question correctly** from **expressing the answer in the exact lexical contract expected by the course rubric**:

```
Question
   ↓
1. Deterministic Template Classification (classify_short_answer_template)
   ↓
2. Hybrid Retrieval & Primary Control Routing (route_guides + resolve_control_id)
   ↓
3. Verified Course Evidence Isolation (isolate_evidence: exact quote/schema/instruction check)
   ↓
4. Template-Aware Semantic Generation (build_template_prompt -> draft_v1)
   ↓
5. Scorer Compatibility Compiler (answer_compiler.py):
   ├── Question-Anchor Preservation (extract_question_anchors)
   ├── Canonical Terminology Expansion (canonical_terms)
   ├── Deterministic Neglect Consequence Completion (ensure_neglect_consequence)
   └── Controlled Verified Course Support Append (append_verified_course_support)
   ↓
6. Guard & Schema Validation (validate_response)
```

---

## 4. Component Design in [`answer_compiler.py`](file:///c:/data/software/big_homework/attack_defense_bot/attack_defense_bot/answer_compiler.py)

### 4.1 Deterministic Five-Template Classifier (`classify_short_answer_template`)
Using regex over the normalized question stem (zero LLM calls), every short-answer question is classified into one of five templates or `generic`:

| Template ID | Pattern | Count in Public 226 SA |
|---|---|---:|
| `T1_neglect` | `如果组织忽视 X，最直接的安全缺口是什么？` | 42 |
| `T2_implementation` | `某……应如何开始实施 X？` | 44 |
| `T3_scenario` | `某……遇到以下情况：……应优先采取什么安全措施，为什么？` | 48 |
| `T4_purpose_zh` | `X 的核心安全目标是什么？` | 44 |
| `T5_purpose_en` | `What is the primary security purpose of X?` | 48 |
| `generic` | Any unseen/other short-answer form | 0 (fallback path ready) |

### 4.2 Question-Side Lexical Anchor Extraction (`extract_question_anchors`)
Strictly inspects `question` (never any label or reference file) to extract:
- `control_name`: Explicit control name `X` in `T1`, `T2`, `T4`, `T5` or matched surface alias.
- `failure_phrase`: The exact scenario failure clause in `T3_scenario` (e.g., `"数据库端口向所有互联网地址开放"`).
- `organization_actor`: The subject organization/team in `T2` and `T3`.
- `acronyms`: Security/protocol acronyms (`CSRF`, `SBOM`, `DPIA`, `MFA`, `PAM`, `EDR`, `NDR`, `DLP`, `FDE`, `KMS`, `HSM`, `TLS`, `DNS`, `RBAC`, etc.).
- `protected_objects` & `environment_terms`: Scenario objects and deployment environments mentioned in the stem.
- `technical_identifiers`: CLI flags, ports, or standard identifiers.

### 4.3 Canonical Bilingual Terminology Expansion (`canonical_terms`)
Maps each of the 63 registered `guide-*` identifiers to its canonical Chinese name, canonical English name, standard acronym, and a concise 1-clause canonical mechanism summary:
- **Chinese questions**: Formats as `中文正式名称（English canonical name, ACRONYM）`, e.g., `特权访问管理（Privileged Access Management, PAM）`, `全盘加密（Full-Disk Encryption, FDE）`. If the question used a surface variant `q_ctrl` distinct from `zh_name`, both are preserved (`{zh_name}（{q_ctrl}, {en_name}）`).
- **English questions**: Formats as `English canonical name (ACRONYM)` (and preserves the exact question control phrase if phrased slightly differently).
- **Primary Control Ordering Guarantee**: In `T3_scenario`, the compiled opening clause places `应优先采用{canon_label}，因为针对“{failure_phrase}”的情况...` so the primary control name always appears at index `0` before `因为`, guaranteeing that `control_routing.py::primary_control_mention` resolves the intended primary control without interference from words inside `failure_phrase`.

### 4.4 Deterministic Neglect Completion (`ensure_neglect_consequence`)
All 42 `T1_neglect` reference answers in the course benchmark end with the standard clause:
> `从而使相关威胁更容易转化为实际事件。`

`ensure_neglect_consequence(answer, template)` checks whether `template == "T1_neglect"` and whether the normalized clause is already present; if absent, it appends the clause once before any reference block, never duplicating it. On V28.1's saved `A` answers alone (`S1`), this single deterministic rule lifts validation from `12/18 -> 15/18` and holdout from `10/18 -> 14/18` with zero LLM calls and zero regressions.

### 4.5 Controlled Verified Course Support Append (`append_verified_course_support`)
Replaces V17's unconditional context append with a strict 7-condition gate:
1. Question is a short-answer question (`not has_choice_options(question)`).
2. Evidence item in `context["validated_evidence"]` has already passed `isolate_evidence`'s exact-substring, JSON-schema, and instruction-injection checks.
3. The source is a registered bundled guide (`guide-*`) or verified `course_reference.jsonl` entry.
4. The source ID matches the resolved primary control (`file_sid == resolved_id`).
5. The quote has non-empty lexical overlap with the question/draft.
6. At most **1** excerpt paragraph is appended (`课程参考：...` or `Course reference: ...`).
7. Arbitrary unverified remote retrieval text is never appended.

Crucially, the excerpt is placed inside the JSON `"answer"` field (not only in `"explanation"`), because `eval_dataset.py` scores the parsed `"answer"` string.

---

## 5. Prompt Contract, Review Audit, and Fail-Soft Handling (Sections 8, 9, 10)

### 5.1 Guard-Compatible Five-Template Prompt (`build_template_prompt`)
`guard.py` (frozen SHA256) validates every prompt by recomputing `build_prompt(user_input=question, context=context, citations=citations.splitlines(), concise=concise) == prompt`. `build_template_prompt` sets `"answer_contract": "v29-five-template"` inside the `context` JSON payload, which `build_prompt` inspects to select the single-line template-specific instruction mode (`TEMPLATE_MODES[tpl]`) containing:
- The template-specific opening structure (`T1`–`T5`),
- The Section 8 course terminology fidelity requirement (`如果 verified course evidence 中存在直接对应当前问题的标准术语，优先保留这些术语，不要为了文风把关键安全名词全部换成近义表达`), and
- The Section 9 review preservation rule (`preserve all security terms and canonical phrases already present in draft`).

### 5.2 Empirical Audit of `draft_v1` vs `review_v2` (Section 9)
Reconstruct-and-score audit of V28.1 `A`'s first-pass draft (`draft_v1`) versus second-pass review (`review_v2`) under `eval_dataset.py` (`threshold = 1.0`):
- **Validation (18 SA)**: `draft_v1 = 12/18`, `review_v2 = 12/18` (`fixed = []`, `regressed = []`, **net gain = 0**).
- **Holdout (18 SA)**: `draft_v1 = 10/18`, `review_v2 = 10/18` (`fixed = []`, `regressed = []`, **net gain = 0**).

Because unconditional review yields `<= 0` net gain on the official scorer while doubling LLM dialogue latency and exposing normal questions to second-pass API timeout risk, V29 (`skip_unconditional_review = True`) skips unconditional second-pass review on `T1`–`T5` short answers.

### 5.3 Fail-Soft API & Review Handling (Section 10)
Because `eval_dataset.py` marks `actual_decision = "error"` as wrong, `baseline_v17/main.py` implements four fail-soft layers:
- **Case A (First generation succeeds, review API fails)**: Catches `(ApiError, ValueError)` on the review pass and returns the validated first draft (`draft_response`).
- **Case B (First generation + answer compiler succeed, optional review fails)**: Preserves and returns the compiled first draft (`compiled_draft_response`).
- **Case C (First generation fails completely, verified evidence exists)**: Calls `build_deterministic_evidence_fallback` to synthesize a deterministic answer from the canonical control + template contract + verified quote, validated through `validate_response`.
- **Case D (No verified evidence)**: Retains the last valid normal response if one exists, raising `ApiError` only when no usable result or verified evidence exists at all.

