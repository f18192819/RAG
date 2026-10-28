# 安全 RAG 助手 — 2024012348

基于第四、六讲实现可追溯问答、结构化证据隔离和混合检索。只需 Python 3.10+ 与 requests；运行不依赖公开评测数据、课件、报告、工作区外文件或第三方模型服务。

## 运行

```powershell
python -m pip install -r requirements.txt
python setup_token.py --token-file "C:\个人路径\2024012348.token.json"
python main.py --query "全盘加密如何管理恢复密钥？"
python main.py
```

配置从本目录 `.env` 读取，环境变量优先。Token 仅进入课程 API 的 Bearer 请求头，不进入模型上下文或日志。课程内网默认绕过互联网代理。

## 数据与检索

- `knowledge/nist_controls.json`：从 NIST 官方 OSCAL 目录提取有效控制项，过滤已撤销条目，保留控制编号和来源。
- `knowledge/additional_guidance.json`：OWASP 实施指南及 NIST 存储加密指南，按章节、段落切块，附文档与章节上下文。
- `knowledge/control_guides.json` 与 `technical_guides.json`：根据官方来源编写的双语控制摘要，结合开发集错误分析补齐遗漏的机制。未存储题目与答案对、样本ID或选项标签。
- `knowledge/lecture_guides.json`：第四、六讲的15条中英文摘要，保留课件页码，覆盖指令权限、结构化证据隔离、语料治理、查询变换、混合检索、覆盖检查及四项RAG评估指标。
- `knowledge/course_reference.jsonl`：从允许读取的 `common_dataset` 获取的 16,000 条课程原始参考文档，保留公共文档编号和文本。它是课程提供的问答形式知识资料，与 `public_dataset.jsonl` 开发评测集分开；不含该评测集的标签或概念评分规则。启动时使用 Python 标准库 SQLite FTS5 在内存建立问题与正文分栏的 BM25 索引，精确术语检索与公共向量检索互补；未提供 FTS5 时平稳退回其他检索路径。
- 公共库 `common_dataset` 只读；个人向量库通过 `RAG_PERSONAL_DATABASE` 配置。未配置个人库时仍可使用打包的本地 BM25 与公共向量库。
- 检索保留原查询并生成一个有长度和数量限制的术语改写；生成的改写仅用于搜索，不能作为事实证据。
- 公共向量、个人向量和本地 BM25 通过 RRF 融合，按来源标识跨路去重，不直接比较不同检索器的原始分数。上下文预算按实际保留内容计费。
- 场景简答题可通过固定目录的语义路由选择最直接相关的资料；路由只能返回白名单编号，不能产生新事实。向量命中编号可回填打包的完整父文档，避免旧版本或截断片段丢失关键条件。
- 明确命名的控制先按规范名称与同义名称匹配，避免把身份生命周期混成密钥生命周期。选择题保留相关控制资料；仅对正向实施题，使用已验证来源中的稀有机制词进行保守匹配，足够大的优势才校正泛化选项。否定题、来源不符、弱匹配或选项自身否定时不采用这一校正。
- 短控制名称选项只有在四个不同选项均有定义时才可采用整组参考，避免只找到干扰项就排除正确资料。语义路由仅作为检索提示，不能独自证明某条指南足以回答问题。

## 提示词隔离

1. 输入先进行字符规范化和注入风险检查；区分“是否应该”“判断正误”等知识讨论与实际越权执行请求。
2. 检索结果经过段落污染过滤及去重。独立 `EVIDENCE_EXTRACTOR` 仅抽取 `fact / quote / source_id`，不负责回答或执行命令。
3. 校验只允许固定字段，限制数量与长度，要求引用确实是对应来源中的连续原文，拒绝越权指令；系统提示词等名词本身不视作执行命令。无效抽取降级为相关原文句子的保守抽取。
   对课程参考问答的精确匹配，另要求问题规范化后完全相同、编号与正文均匹配本地来源，再保留参数原文；不会仅凭相近问题或来源标签跳过检查。
   本次经认证的公共库原始响应也可作为来源记录，因此不受本地16,000条快照范围限制；仅记录公共库实际返回的编号与内容。问题匹配保留运算符、标识符、CLI参数及大小写，避免把不同技术问题合并。
4. 最终问答模型只看到通过检查的证据；原始检索文档被丢弃。相关的主控制摘要需在打包来源中存在且与检索来源逐字一致，才能完整保留。
5. 问题、证据和来源标签进行 NFKC 规范化、控制字符清理与 HTML 转义。模板固定分区顺序，附版本及摘要；重建校验检测结构和内容修改。摘要校验不替代身份认证或语义防护。
6. 显式区分选择题和简答题。明确对应单一控制的概述类简答可直接采用经过原文检查的来源说明，避免生成与来源矛盾的额外机制；其他简答经过草稿复核。判断、比较、参数及复杂设计任务保留相应生成路径。
7. 最终输出检查 JSON、decision、非空答案、引用编号及凭据泄露；拒答统一清空答案。格式失败最多重新生成一次。

课程 API 的 `custom_prompt` 与 `user_input` 最终仍为文本拼接；这些措施降低注入风险，不等同于模型原生权限隔离。引用存在也不等同于事实已经得到完整语义证明。

## 验证

```powershell
python -m unittest discover -s tests -v
python eval_offline.py --dataset "C:\数据路径\public_dataset.jsonl" --output-dir output/offline
python eval_dataset.py --dataset "C:\数据路径\public_dataset.jsonl" --concurrency 3 --progress-every 20 --output-dir output/online
```

评估脚本保留课程接口和评分定义。公开数据仅用于本地开发评测，不打包进提交文件。平台隐藏集成绩以课程排行榜为准，离线护栏指标不代表问答正确率。检索和推理遇到短暂网络错误会有限重试，不自动重试建库或上传等写操作。

## 资料来源

- NIST SP 800-53 Rev.5：[官方目录](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)、[OSCAL 来源版本](https://github.com/usnistgov/oscal-content/tree/v1.4.0)。
- [NIST SP 800-111 存储加密](https://csrc.nist.gov/pubs/sp/800/111/final)、[SP 800-207 零信任](https://csrc.nist.gov/pubs/sp/800/207/final)、[SP 800-218 安全开发](https://csrc.nist.gov/pubs/sp/800/218/final)、[SP 800-193 固件韧性](https://csrc.nist.gov/pubs/sp/800/193/final)。
- [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries)：打包摘录保留来源与归属，原指南依其 CC BY-SA 4.0 许可提供。
- [EDPB 控制者与处理者](https://www.edpb.europa.eu/sme/learn-the-basics/data-controller-or-data-processor_en)、[国际数据传输](https://www.edpb.europa.eu/sme/be-compliant/international-data-transfers_en)：涉及具体司法辖区，不能泛化为全球统一法律。
- [Hines 等，Spotlighting](https://arxiv.org/abs/2403.14720)：不可信数据的边界、标记及编码隔离思路。
- [CISA 等，The Case for Memory Safe Roadmaps](https://www.cisa.gov/sites/default/files/2023-12/The-Case-for-Memory-Safe-Roadmaps-508c.pdf)：内存安全语言预防缺陷类别，与运行时隔离限制影响的区别。
- [Anthropic，Contextual Retrieval](https://www.anthropic.com/research/contextual-retrieval)：上下文补充、词法与语义检索互补的思路。

## 提交

压缩包只有单层 `attack_defense_bot/`，包含代码、必要的本地参考语料和课程评测所需私密配置；不包含开发评测集、日志、报告或缓存。带 `.env` 的课程包仅交课程指定平台。分享源码时移除真实 `.env`，使用 `.env.example`。
