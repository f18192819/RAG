# 安全 RAG 课堂练习：V28.1

V28.1 修复候选来源在融合和证据抽取阶段丢失、回答机制遗漏，以及排除基线的错误选型门槛。默认保留 A 基线；新配置须在固定验证集和最终保留集同时不低于基线，才可启用。

本轮 A/H/H1/H2/H3 对照与发布结论见 [V28_1_RESULTS.md](V28_1_RESULTS.md)。本轮不会自动上传平台。

历史 V28 平台提交为正常题77.027%、攻击识别100%，低于历史最好87.8378%；该结果保留在旧报告中，不能算作 V28.1 成绩。

- [V28.1 真实对照与发布结论](V28_1_RESULTS.md)
- [V28 历史设计与限制](V28_CLEAN_DESIGN.md)
- [V28 历史消融和平台测试](ABLATION_RESULTS.md)
- [V28 历史混淆诊断（含已知阶段误标）](CONTROL_CONFUSION.md)
- [代码与运行说明](attack_defense_bot/attack_defense_bot/README.md)
- [冻结实验和逐题诊断](experiments/v28/)

运行 `python tools/verify_v28_1.py` 验证生产主链、安全合同及打包。真实凭据从仓库外配置，不进入 ZIP 或当前 Git 树；历史提交中的旧凭据需要更换。
