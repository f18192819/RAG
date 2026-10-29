# V28.1：准确率回退修复与基线发布门槛

起点：`f2868e6`。本轮实际运行 A/H/H1/H2/H3 的固定验证集及保留集，对所有输出使用同一严格评分器。没有上传课堂平台，也没有新增运行时题目特判或修改知识源。

**最终默认：A。新候选允许提交平台：否。** 验证集预选 A；保留集只确认或否决，没有重新选型。

H3 最终语义正确率：验证集 88.89%（A：88.89%），保留集 92.59%（A：92.59%）。但验证集首要控制为 96.30%，A 为 100.00%，因此本轮只能说最终语义已恢复到基线水平，不能说综合发布门槛已经通过。

## 修复内容

1. 候选生成和使用分开。候选保留开启时，独立检索的实际融合结果进入最终决策；最多三份候选指南预留上下文位置，ID 传入 evidence isolation。指南只有在实际正文匹配注册来源、引文及 schema 检查通过后才能成为证据，不能只凭 metadata 获得事实权威。
2. 充分回答模式要求主控制、直接原因、相关核心机制及必要验证，不再给简答设置过短的固定字数上限。只有来源控制冲突，或短答案对多条已验证来源机制覆盖明显不足时，触发一次条件复核；充分草稿不重复复核。没有追加整段指南或关键词填充。词汇覆盖只作复核触发信号，不作正确性判据，仍可能漏报或误触发。
3. A 纳入候选。先看最终语义正确率，再看首要控制；最终正确率、首要控制和 recall@3 均不得低于 A。安全召回100%、正常误拒0、推理错误0也是门槛。完全同分保留 A；保留集只能否决已选新方案。
4. 默认入口已支持真实 A 路径：保留 v17 的检索、生成和独立复核，使用当前护栏和外部凭据；取消 v17 最后追加的来源段落。旧严格评分本来就剥离这些段落，因此它们不再掩盖 synthesis。A 的运行时代码位于 `baseline_v17/`，不依赖实验目录或开发标签。

## 同条件真实模型对照

沿用 v28 的固定 split：每个评估子集27题（9选择、18简答）。相同知识源快照、模型服务、温度0、输出预算1000 tokens、top_k=5、上下文5份/6000字符、个人库关闭、并发4。使用本轮新缓存，各版本完全相同请求共享响应；没有复用旧轮生成结果。H 从原提交固定，H1 不改生成策略，H2 不改候选保留策略。本轮 H 是旧代码的新一轮响应及评分，不必与旧报告逐字或逐分相同；跨轮服务输出及自动评分并非完全确定。A 使用自己的 v17 检索与复核行为，候选链的开关不作用于 A。

### validation

| 版本 | target-control | recall@3 | evidence survival | final semantic | 选择题 | 简答题 | attack recall（输入护栏） | benign false-reject（模型） |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A v17 基线（当前护栏、不追加来源） | 100.00% | 85.19% | 70.83% | 88.89% | 100.00% | 83.33% | 100.00% | 0.00% |
| H 原 f2868e6 生产逻辑 | 92.59% | 85.19% | 62.96% | 66.67% | 100.00% | 50.00% | 100.00% | 0.00% |
| H1 仅修复候选保留 | 92.59% | 85.19% | 77.78% | 74.07% | 100.00% | 61.11% | 100.00% | 0.00% |
| H2 仅恢复答案完整性 | 92.59% | 85.19% | 62.96% | 81.48% | 100.00% | 72.22% | 100.00% | 0.00% |
| H3 两项同时修复 | 96.30% | 85.19% | 77.78% | 88.89% | 100.00% | 83.33% | 100.00% | 0.00% |

evidence survival 的分母为候选目录检索到正确规范控制的题数；全体样本的阶段存活另列。只按注册 source ID 统计，语义等价但没有该 ID 的外部材料不会被算作该指南。

实际预留指南核查：H1 / H3 各有 15 / 15 条普通场景进入保留策略，经过 fusion、prepare、evidence 的预留指南丢失分别为 0 / 0。这不保证正确控制一定进入Top3；未进入Top3仍是候选召回瓶颈。

| 版本 | 来源存活 retrieval → fusion → prepare → evidence（全体分母） | 失败阶段计数 | 推理错误 | 评分错误 | 条件复核次数 |
|---|---|---|---:|---:|---:|
| A | 88.89% → 62.96% → 62.96% → 62.96% | `{"none": 24, "evaluation_error": 1, "generation_incomplete": 2}` | 0 | 1 | 基线常规独立复核 |
| H | 100.00% → 62.96% → 62.96% → 62.96% | `{"none": 18, "fusion_loss": 4, "generation_incomplete": 4, "evaluation_error": 1}` | 0 | 1 | 0（失败0） |
| H1 | 100.00% → 77.78% → 77.78% → 77.78% | `{"none": 20, "evaluation_error": 1, "fusion_loss": 2, "generation_wrong_primary": 1, "generation_incomplete": 3}` | 0 | 1 | 1（失败0） |
| H2 | 100.00% → 62.96% → 62.96% → 62.96% | `{"none": 22, "fusion_loss": 3, "generation_incomplete": 1, "evaluation_error": 1}` | 0 | 1 | 1（失败0） |
| H3 | 100.00% → 77.78% → 77.78% → 77.78% | `{"none": 24, "fusion_loss": 1, "generation_incomplete": 2}` | 0 | 0 | 4（失败0） |

| 版本 | 相比 H 修复 / 引入回归（最终语义） | 相比 A 修复 / 引入回归（最终语义） |
|---|---:|---:|
| A | 7 / 1 | 0 / 0 |
| H | 0 / 0 | 1 / 7 |
| H1 | 2 / 0 | 1 / 5 |
| H2 | 4 / 0 | 1 / 3 |
| H3 | 6 / 0 | 1 / 1 |

逐题对照（✓=严格语义通过，×后列首个观察到的失败阶段；评分错误独立标记）：

| question_id | 正确控制 | A | H | H1 | H2 | H3 |
|---|---|---|---|---|---|---|
| public-normal-train-syn-0010 | guide-data-classification | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0011 | guide-data-classification | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0014 | guide-data-classification | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0127 | guide-endpoint-privilege | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0131 | guide-endpoint-privilege | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0140 | guide-endpoint-privilege | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0185 | guide-xss | × evaluation_error | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0188 | guide-xss | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0193 | guide-xss | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0310 | guide-ndr | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0314 | guide-ndr | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0319 | guide-ndr | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0408 | guide-integrity | ✓ | × fusion_loss | × fusion_loss | ✓ | ✓ |
| public-normal-train-syn-0409 | guide-integrity | ✓ | × generation_incomplete | ✓ | ✓ | ✓ |
| public-normal-train-syn-0412 | guide-integrity | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0422 | guide-cloud-iam | ✓ | × fusion_loss | × fusion_loss | × fusion_loss | × fusion_loss |
| public-normal-train-syn-0432 | guide-cloud-iam | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0434 | guide-cloud-iam | ✓ | × generation_incomplete | × generation_incomplete | × evaluation_error | ✓ |
| public-normal-train-syn-0576 | guide-vulnerability | ✓ | × fusion_loss | × evaluation_error | × fusion_loss | ✓ |
| public-normal-train-syn-0582 | guide-vulnerability | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0588 | guide-vulnerability | ✓ | × generation_incomplete | ✓ | ✓ | ✓ |
| public-normal-train-syn-0646 | guide-identity | × generation_incomplete | × fusion_loss | × generation_incomplete | × fusion_loss | × generation_incomplete |
| public-normal-train-syn-0651 | guide-identity | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0658 | guide-identity | × generation_incomplete | × generation_incomplete | × generation_incomplete | × generation_incomplete | × generation_incomplete |
| public-normal-train-syn-0703 | guide-sandbox | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0705 | guide-sandbox | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0714 | guide-sandbox | ✓ | × evaluation_error | × generation_wrong_primary | ✓ | ✓ |

完整答案、引文核验、机制判定和各阶段来源见对应 `*_details.jsonl`；逐题修复/回归的结构化字段见 `paired_comparison.json`。

### holdout

| 版本 | target-control | recall@3 | evidence survival | final semantic | 选择题 | 简答题 | attack recall（输入护栏） | benign false-reject（模型） |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A v17 基线（当前护栏、不追加来源） | 100.00% | 96.30% | 66.67% | 92.59% | 100.00% | 88.89% | 100.00% | 0.00% |
| H 原 f2868e6 生产逻辑 | 85.19% | 96.30% | 81.48% | 77.78% | 100.00% | 66.67% | 100.00% | 0.00% |
| H1 仅修复候选保留 | 100.00% | 96.30% | 92.59% | 88.89% | 100.00% | 83.33% | 100.00% | 0.00% |
| H2 仅恢复答案完整性 | 96.30% | 96.30% | 81.48% | 85.19% | 100.00% | 77.78% | 100.00% | 0.00% |
| H3 两项同时修复 | 100.00% | 96.30% | 92.59% | 92.59% | 100.00% | 88.89% | 100.00% | 0.00% |

evidence survival 的分母为候选目录检索到正确规范控制的题数；全体样本的阶段存活另列。只按注册 source ID 统计，语义等价但没有该 ID 的外部材料不会被算作该指南。

实际预留指南核查：H1 / H3 各有 10 / 10 条普通场景进入保留策略，经过 fusion、prepare、evidence 的预留指南丢失分别为 0 / 0。这不保证正确控制一定进入Top3；未进入Top3仍是候选召回瓶颈。

| 版本 | 来源存活 retrieval → fusion → prepare → evidence（全体分母） | 失败阶段计数 | 推理错误 | 评分错误 | 条件复核次数 |
|---|---|---|---:|---:|---:|
| A | 100.00% → 66.67% → 66.67% → 66.67% | `{"none": 25, "evaluation_error": 1, "generation_incomplete": 1}` | 0 | 1 | 基线常规独立复核 |
| H | 100.00% → 81.48% → 81.48% → 81.48% | `{"none": 21, "fusion_loss": 2, "generation_wrong_primary": 3, "evaluation_error": 1}` | 0 | 1 | 0（失败0） |
| H1 | 100.00% → 92.59% → 92.59% → 92.59% | `{"none": 24, "evaluation_error": 3}` | 0 | 3 | 0（失败0） |
| H2 | 100.00% → 81.48% → 81.48% → 81.48% | `{"none": 23, "fusion_loss": 2, "evaluation_error": 2}` | 0 | 2 | 2（失败0） |
| H3 | 100.00% → 92.59% → 92.59% → 92.59% | `{"none": 25, "evaluation_error": 1, "generation_incomplete": 1}` | 0 | 1 | 3（失败0） |

| 版本 | 相比 H 修复 / 引入回归（最终语义） | 相比 A 修复 / 引入回归（最终语义） |
|---|---:|---:|
| A | 4 / 0 | 0 / 0 |
| H | 0 / 0 | 0 / 4 |
| H1 | 4 / 1 | 1 / 2 |
| H2 | 2 / 0 | 0 / 2 |
| H3 | 4 / 0 | 0 / 0 |

逐题对照（✓=严格语义通过，×后列首个观察到的失败阶段；评分错误独立标记）：

| question_id | 正确控制 | A | H | H1 | H2 | H3 |
|---|---|---|---|---|---|---|
| public-normal-train-syn-0045 | guide-transfer | ✓ | × generation_wrong_primary | × evaluation_error | × evaluation_error | ✓ |
| public-normal-train-syn-0049 | guide-transfer | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0053 | guide-transfer | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0099 | guide-allowlist | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0101 | guide-allowlist | ✓ | × generation_wrong_primary | ✓ | ✓ | ✓ |
| public-normal-train-syn-0106 | guide-allowlist | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0239 | guide-sca | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0240 | guide-sca | × generation_incomplete | × fusion_loss | ✓ | × fusion_loss | × generation_incomplete |
| public-normal-train-syn-0243 | guide-sca | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0295 | guide-dns | × evaluation_error | × evaluation_error | × evaluation_error | × evaluation_error | × evaluation_error |
| public-normal-train-syn-0301 | guide-dns | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0305 | guide-dns | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0379 | guide-masking | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0388 | guide-masking | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0389 | guide-masking | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0479 | guide-cloud-kms | ✓ | × generation_wrong_primary | ✓ | ✓ | ✓ |
| public-normal-train-syn-0483 | guide-cloud-kms | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0487 | guide-cloud-kms | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0533 | guide-recovery | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0534 | guide-recovery | ✓ | × fusion_loss | ✓ | × fusion_loss | ✓ |
| public-normal-train-syn-0545 | guide-recovery | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0590 | guide-mfa | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0593 | guide-mfa | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0602 | guide-mfa | ✓ | ✓ | × evaluation_error | ✓ | ✓ |
| public-normal-train-syn-0729 | guide-random | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0731 | guide-random | ✓ | ✓ | ✓ | ✓ | ✓ |
| public-normal-train-syn-0733 | guide-random | ✓ | ✓ | ✓ | ✓ | ✓ |

完整答案、引文核验、机制判定和各阶段来源见对应 `*_details.jsonl`；逐题修复/回归的结构化字段见 `paired_comparison.json`。

## 诊断及评分解释

`retrieval_miss`：目录与实际融合均未找到正确来源；`fusion_loss`：候选存在但融合丢失；`context_loss`：融合存在但 prepare 裁剪丢失；`evidence_extraction_miss`：已进入上下文但证据抽取未保留；`generation_wrong_primary` / `generation_incomplete`：来源存活但首要控制错误/机制不全。只有实际执行了有效 reranker 且将候选排除才可记 `rerank_miss`。`evaluation_error` 不冒充生成错误。阶段是定位线索，不是因果归因。

候选召回按筛选前的控制目录排序计数，实际有界Top3另见 `router.candidate_controls`。目录到fusion的丢失也可能包括Top3预算筛选，不能全部归因RRF权重；逐题文件另存 `bounded_candidate_present` 及预留ID，真实预留存活核查见 `candidate_survival_audit.json`。

评分先判主要控制、再看机制；选择题严格核对字母。盲控制分类只看实际 synthesis 和来源目录，不看标准答案；机制评分仅在推理完成后使用参考答案。评分必须给出实际答案的精确引用，覆盖至少80%的核心参考要求才能通过。JSON/引文校验失败保守计错且单列，没有挑选有利重评分。

评分与被测模型来自同一服务，不等同独立专家标注。全部数据曾用于历史开发，holdout 只作固定回归最终确认，不能证明隐藏分布不回退；27题的小样本尤其不能保证平台成绩。

## 测试、安全与发布决定

84 项测试通过，failures=0，errors=0。含原安全测试、10组边界40个子用例、九类机制完整性、候选生存、完整答案不重复复核、A默认分派、基线复核保留，以及选型/诊断门槛。模拟模型测试不代替上述真实模型评测。

输入护栏未修改：TP=177，TN=626，FP=0，FN=0。正常输入误拒率0%；模型正常题误拒另列于表。外部凭据管理继续保留，ZIP与待提交源码均不得含真实Token或评测标签。

最终发布判断：

```json
{
  "validation_selected": "A",
  "holdout_used_to_reselect": false,
  "holdout_nonregression_checks": {
    "final_semantic": true,
    "primary_control": true,
    "recall_at_3": true,
    "operational_errors": true,
    "attack_recall": true,
    "benign_false_reject": true
  },
  "validation_baseline_checks": {
    "H": {
      "final_semantic": false,
      "primary_control": false,
      "recall_at_3": true,
      "operational_errors": true,
      "attack_recall": true,
      "benign_false_reject": true
    },
    "H1": {
      "final_semantic": false,
      "primary_control": false,
      "recall_at_3": true,
      "operational_errors": true,
      "attack_recall": true,
      "benign_false_reject": true
    },
    "H2": {
      "final_semantic": false,
      "primary_control": false,
      "recall_at_3": true,
      "operational_errors": true,
      "attack_recall": true,
      "benign_false_reject": true
    },
    "H3": {
      "final_semantic": true,
      "primary_control": false,
      "recall_at_3": true,
      "operational_errors": true,
      "attack_recall": true,
      "benign_false_reject": true
    }
  },
  "release_reason": "validation_kept_baseline",
  "new_candidate_release_allowed": false,
  "default_variant": "A",
  "deployed_profile": {
    "selected_variant": "A",
    "production_profile": "A",
    "query_representation": false,
    "contrastive_rerank": false,
    "candidate_retention": false,
    "answer_completeness": false,
    "selection_status": "baseline_retained"
  },
  "package_fingerprint": "f66519252c656a7ca85ab9df8ebfb048191eda510e9a9ca7130f2c5c8cb21ade",
  "platform_uploaded_this_round": false
}
```

本轮平台上传次数：**0**。历史 V28 的77.027%不是本轮成绩。若门槛未通过，默认保留 A，禁止用本轮新候选上传；即使回归门槛通过，也只表示达到下一次平台验证的技术门槛，不等于已经提高平台成绩。

## 复现入口

```powershell
python tools/verify_v28_1.py
python experiments/v28_1/run_experiments.py
python experiments/v28_1/score_experiments.py
python experiments/v28_1/finalize.py select
python experiments/v28_1/run_experiments.py --split holdout
python experiments/v28_1/score_experiments.py --split holdout
python experiments/v28_1/finalize.py release
python tools/render_v28_1_reports.py
```

已有结果和冻结选择拒绝覆盖。新一轮复现应使用独立结果目录副本，不能删除当前记录后据错题调参。来源、代码、split和评分器指纹随 JSON 保存；请求与评分缓存留本地，不上传仓库。
