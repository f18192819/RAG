"""Canonical names and technical signals, sourced from the cited guides."""
from pathlib import Path
import json

root=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
updates={
    'guide-dpia':{
        'title':'Data protection impact assessment (DPIA) / 数据保护影响评估',
        'aliases':'data protection impact assessment privacy impact assessment DPIA PIA 数据保护影响评估 高风险个人数据 隐私风险 必要性 相称性'},
    'guide-dns':{
        'aliases':'DNS安全监测 域名 解析 DNS隧道 恶意域名 查询字符熵 高熵子域名 新域名 查询频率 domain entropy DNS tunneling novel subdomains'},
    'guide-cloud-kms':{
        'title':'Managed key services (cloud KMS) / 托管密钥服务',
        'aliases':'managed key services cloud key management service KMS HSM 托管密钥服务 数据加密密钥 云加密密钥 信封加密 主密钥 密码运算 权限隔离'},
    'guide-sast-dast':{
        'title':'Static and dynamic security testing (SAST and DAST) / 静态与动态安全测试',
        'aliases':'static and dynamic security testing SAST DAST 静态与动态安全测试 代码扫描 运行应用 测试门禁 自动测试 缺陷发现前移 流水线 修复门禁 shift-left security testing manual post-release discovery'},
}
for path in [root/'control_guides.json',root/'technical_guides.json']:
    obj=json.loads(path.read_text(encoding='utf-8'))
    for doc in obj['documents']:
        if doc['id'] in updates:doc.update(updates[doc['id']])
    path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
print('Updated four canonical routing entries')
