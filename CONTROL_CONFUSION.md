# 控制混淆与阶段存活

这是 f2868e6 的历史 V28 记录。旧 `rerank_miss` 混入了未实际调用排序器时的融合丢失，不能据此归因排序失败。V28.1 已分开检索、融合、上下文、证据抽取与生成遗漏，新的真实对照和逐题诊断见 [V28_1_RESULTS.md](V28_1_RESULTS.md)；本文件保留原始历史数值。

只从已完成真实推理、统一严格重评后的记录生成。计数矩阵包含正确对角线，Top Confusions 排除对角线；unresolved 单列。选择题选错但仍属同一控制时，由 choice_correct=False 判错，控制矩阵本身不能代替字母准确率。

## validation / A

| desired | predicted | count |
|---|---|---:|
| 无观察到的首要控制混淆 | — | 0 |

失败阶段：`{"none": 24, "generation_miss": 2, "retrieval_miss": 1}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 88.89% | 62.96% | 62.96% | 62.96% |

证据模式计数：`{"llm": 8, "deterministic_guide": 18, "fallback": 1}`；fallback 最终语义准确率：100.00%。

## validation / B

| desired | predicted | count |
|---|---|---:|
| 无观察到的首要控制混淆 | — | 0 |

失败阶段：`{"none": 24, "generation_miss": 2, "retrieval_miss": 1}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 88.89% | 62.96% | 62.96% | 62.96% |

证据模式计数：`{"llm": 8, "deterministic_guide": 18, "fallback": 1}`；fallback 最终语义准确率：100.00%。

## validation / C

| desired | predicted | count |
|---|---|---:|
| guide-vulnerability | guide-awareness | 1 |
| guide-endpoint-privilege | guide-least | 1 |
| guide-cloud-iam | guide-least | 1 |
| guide-integrity | unresolved | 1 |

失败阶段：`{"none": 13, "rerank_miss": 14}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 92.59% | 0.00% | 0.00% | 0.00% |

证据模式计数：`{"llm": 26, "fallback": 1}`；fallback 最终语义准确率：100.00%。

## validation / D

| desired | predicted | count |
|---|---|---:|
| guide-vulnerability | guide-awareness | 1 |
| guide-endpoint-privilege | guide-least | 1 |
| guide-integrity | unresolved | 1 |
| guide-cloud-iam | guide-least | 1 |

失败阶段：`{"none": 13, "rerank_miss": 14}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 92.59% | 0.00% | 0.00% | 0.00% |

证据模式计数：`{"llm": 26, "fallback": 1}`；fallback 最终语义准确率：100.00%。

## validation / E

| desired | predicted | count |
|---|---|---:|
| guide-vulnerability | guide-awareness | 1 |
| guide-endpoint-privilege | guide-least | 1 |
| guide-cloud-iam | guide-pam | 1 |

失败阶段：`{"none": 16, "evidence_drop": 9, "rerank_miss": 2}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 92.59% | 7.41% | 7.41% | 7.41% |

证据模式计数：`{"fallback": 2, "llm": 22, "deterministic_guide": 3}`；fallback 最终语义准确率：100.00%。

## validation / F

| desired | predicted | count |
|---|---|---:|
| guide-cloud-iam | guide-least | 1 |
| guide-identity | guide-rbac | 1 |

失败阶段：`{"none": 19, "evidence_drop": 3, "generation_miss": 3, "rerank_miss": 2}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 100.00% | 62.96% | 62.96% | 62.96% |

证据模式计数：`{"deterministic_guide": 17, "llm": 10}`；fallback 最终语义准确率：N/A。

## validation / G

| desired | predicted | count |
|---|---|---:|
| guide-cloud-iam | guide-least | 1 |
| guide-identity | guide-rbac | 1 |

失败阶段：`{"none": 19, "rerank_miss": 4, "generation_miss": 4}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 100.00% | 62.96% | 62.96% | 62.96% |

证据模式计数：`{"deterministic_guide": 17, "llm": 10}`；fallback 最终语义准确率：N/A。

## validation / H

| desired | predicted | count |
|---|---|---:|
| guide-cloud-iam | guide-least | 1 |
| guide-identity | guide-rbac | 1 |

失败阶段：`{"none": 20, "rerank_miss": 3, "generation_miss": 4}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 100.00% | 62.96% | 62.96% | 62.96% |

证据模式计数：`{"deterministic_guide": 17, "llm": 9, "fallback": 1}`；fallback 最终语义准确率：100.00%。

## validation / I

| desired | predicted | count |
|---|---|---:|
| guide-cloud-iam | guide-least | 1 |
| guide-identity | guide-rbac | 1 |

失败阶段：`{"none": 20, "evidence_drop": 2, "rerank_miss": 1, "generation_miss": 4}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 100.00% | 62.96% | 62.96% | 62.96% |

证据模式计数：`{"llm": 9, "deterministic_guide": 17, "fallback": 1}`；fallback 最终语义准确率：100.00%。

## holdout / A

| desired | predicted | count |
|---|---|---:|
| guide-masking | unresolved | 1 |
| guide-sca | guide-inventory | 1 |

失败阶段：`{"none": 22, "rerank_miss": 2, "generation_miss": 3}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 96.30% | 62.96% | 62.96% | 62.96% |

证据模式计数：`{"llm": 8, "deterministic_guide": 18, "fallback": 1}`；fallback 最终语义准确率：100.00%。

## holdout / H

| desired | predicted | count |
|---|---|---:|
| guide-sca | guide-inventory | 1 |

失败阶段：`{"none": 17, "generation_miss": 7, "rerank_miss": 3}`。

来源存活（全体样本分母）：

| retrieval | fusion | prepare | evidence |
|---:|---:|---:|---:|
| 100.00% | 81.48% | 81.48% | 81.48% |

证据模式计数：`{"deterministic_guide": 22, "llm": 5}`；fallback 最终语义准确率：N/A。

## 如何解读

retrieval_miss 表示正确规范控制未进入候选目录；rerank_miss 表示目录中存在但排序未居首；evidence_drop 表示居首后未保留该规范来源；generation_miss 表示正确来源存活但最终语义未通过。首先遇到的条件用于归类，是定位线索，不是因果证明。合法的 exact FAQ 也可能绕过一般检索阶段，不能把缺少该阶段日志等同于回答错误。

完整 desired × predicted 数值矩阵见 `experiments/v28/results/confusion_matrices.json`。

10 组边界测试覆盖 FDE/DLP、DLP/minimization、sandbox/memory、segmentation/security group、awareness/MFA、CSRF/session、DPIA/minimization、allowlist/endpoint privilege、secrets/KMS、firmware/secure boot；未在这 27 条中出现的类别不计为零风险，也不据此增写逐题规则。
