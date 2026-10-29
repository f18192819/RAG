# 安全 RAG：V28 收敛版

正常知识问答与提示词注入防护。源代码不包含个人Token，模型和检索服务由环境提供。

## 运行

```powershell
pip install -r requirements.txt
$env:RAG_API_TOKEN = '<由安全环境提供>'
python main.py --query 'What is least privilege?'
```

也可设置`RAG_TOKEN_FILE`，指向仓库外的本人凭据JSON。默认路径为`~/.config/rag/student.token.json`。`setup_token.py --token-file <外部路径>`仅保存路径，不复制凭据。

默认API为课程服务`http://10.1.0.220:9002/api`，可用`RAG_API_BASE_URL`覆盖。公共库`common_dataset`只读，个人库可通过`RAG_PERSONAL_DATABASE`显式配置；本轮固定实验关闭个人库以统一语料条件。

## 推理流程

原问题与保真特征 → 独立检索 → 最多3个候选控制 → 结构化范围比较 → 保留竞争证据 → 引文校验 → 简洁答案。

上述为可选模块全开的实验路径。固定验证集选定的默认 H 配置关闭模型改写和范围比较，直接以原问题独立检索、校验证据并生成。开关由 `pipeline_profile.json` 提供，`RAG_QUERY_REPRESENTATION` / `RAG_CONTRASTIVE_RERANK` 可覆盖。实验没有证明这两个步骤有正收益，详情见根目录结果报告。

改写不推荐新控制；scope只参与对比排序，不成为答案事实。检索权重集中在`config.py`。低置信度最多补检一次；选择题比较用户提供的选项，不先由通用router裁成唯一控制。

答案不再附加整段资料。只有完全相同的来源FAQ和严格识别的明确概述问题允许抽取式答复。普通问题保留简洁生成结论，检测到来源控制不一致时最多纠正一次。

结构化输出：`decision`、`answer`、`evidence`、`explanation`。恶意越权请求拒绝；正常知识题即使证据不足仍尽力回答，并明确依据不足。

## 资料与可观测性

`knowledge/`保留NIST、OWASP等规范资料、63类来源控制和只读课程参考快照。`course_reference.jsonl`来自允许读取的公共知识库，不来自开发集的question/expected字段。`control_scope.json`是来源适用范围元数据，不索引、不作为事实。

可选诊断记录查询、候选来源、排序、融合、prepare、证据模式与最终答案。不记录提示词、Token或认证配置。日志默认关闭，开发评测通过`capture_diagnostics`逐题启用。

## 从仓库根目录验证

```powershell
python tools/verify_v28.py
python experiments/v28/run_ablations.py --smoke
python experiments/v28/run_ablations.py
```

模拟测试验证协议和主调用链，不等于模型准确率。严格语义评测在`experiments/v28/`，不会进入推理提交包。旧`eval_dataset.py`只作兼容输出；不得用共享关键词通过率替代首要控制判断。

完整设计、真实对照结果和实验限制见仓库根目录的`V28_CLEAN_DESIGN.md`、`ABLATION_RESULTS.md`及`CONTROL_CONFUSION.md`。
