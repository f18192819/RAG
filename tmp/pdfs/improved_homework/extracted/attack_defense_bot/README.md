# 安全 RAG 助手（改进版）

姓名：房楷涵　学号：2024012348

## 运行

使用 Python 3.10 或更新版本，连接校园网或课程 VPN，在本目录执行：

```powershell
python -m pip install -r requirements.txt
python setup_token.py --token-file "C:\路径\2024012348.token.json"
python main.py --query "什么是最小权限原则？"
```

也可复制 `.env.example` 为 `.env` 后填写 `RAG_API_TOKEN`。环境变量优先于 `.env`；代码包不附带个人 Token。
默认检索只读公共库 `common_dataset`，单次问答不需要本地公开数据集。程序输出包含 `decision`、`answer`、`evidence`、`explanation` 的 JSON。

## 实现

`main.py` 串联输入校验、检索、上下文整理、提示词构建、模型生成和输出校验。
`guard.py` 处理规范化、组合风险规则、模板检查和响应检查；`prompt_builder.py` 转义外部数据并定义固定输出约束。
`data_processor.py` 负责污染段落清理、去重、轻量重排、字符预算和引用对齐。
`api_client.py`、`config.py` 负责接口调用、参数校验、凭据脱敏及内网代理处理。

## 验证与复现

```powershell
python -m unittest discover -s tests -v
python eval_offline.py --dataset "C:\路径\public_dataset.jsonl" --output-dir output/offline
python smoke_api.py --output output/api_smoke.json
python eval_dataset.py --dataset "C:\路径\public_dataset.jsonl" --concurrency 5 --short-answer-policy concepts --short-answer-concept-threshold 0.5 --progress-every 25 --output-dir output/full_online
```

本次打包从解压后的代码执行离线测试。历史在线全量评估完成于 2026-10-18，指标见同交的进度报告；2026-10-25 未重跑在线全量评估。
`eval_offline.py` 中保留的 baseline 关键词统计仅用于比较输入护栏，不是另一套原始课程实现。
`smoke_api.py` 会创建或复用个人演示库并上传自编摘要；不会写入或删除公共库。
公开集参与过开发，成绩不代表隐藏集。引用范围检查不能保证资料在语义上支持答案，多轮记忆模块保留但主链路未启用。
