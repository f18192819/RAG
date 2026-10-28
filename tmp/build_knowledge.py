"""Build a bundled retrieval corpus from the official NIST OSCAL catalog.
No evaluation questions or answers are consumed by this script.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALIASES = {
    'ac-2': '账户管理 身份生命周期 入职转岗离职 身份权限评审 JML identity lifecycle account review',
    'ac-3': '访问控制 授权访问 身份鉴别 RBAC ABAC access control authorization',
    'ac-4': '信息流控制 数据流转 出站流量 egress network flow',
    'ac-5': '职责分离 双人审批 separation of duties',
    'ac-6': '最小权限 特权访问管理 临时权限 高权限审批 PAM privileged access management JIT',
    'ac-7': '登录失败 暴力破解 密码喷洒 速率限制 brute force rate limiting',
    'ac-11': '设备锁定 锁屏 device lock',
    'ac-12': '会话终止 会话超时 session timeout',
    'ac-17': '远程访问 远程运维 VPN ZTNA remote access',
    'ac-18': '无线网络 WiFi wireless',
    'ac-19': '移动设备 BYOD MDM mobile device',
    'at-2': '安全意识培训 钓鱼演练 phishing simulation security awareness',
    'au-2': '审计日志 安全日志 事件记录 audit logging',
    'au-3': '日志字段 操作主体 时间 对象 结果 audit event content',
    'au-6': '集中日志关联 SIEM 安全事件管理 告警关联 centralized logging correlation',
    'au-8': '时间同步 日志时间 戳 timestamp NTP',
    'au-9': '日志防篡改 审计日志保护 immutable logging',
    'au-11': '日志保留 审计记录保存 audit retention',
    'ca-2': '控制有效性 审计证据 安全控制评估 audit evidence control assessment',
    'ca-5': '整改闭环 风险负责人 整改计划 复测 remediation tracking',
    'ca-7': '持续监控 云配置态势管理 错误配置 公开存储桶 CSPM cloud security posture management',
    'ca-8': '渗透测试 授权测试 penetration testing',
    'cm-2': '安全配置基线 基线加固 配置漂移 hardening configuration baseline',
    'cm-3': '变更控制 变更审批 回滚 change management rollback',
    'cm-6': '安全配置 配置漂移 错误配置 configuration settings',
    'cm-7': '最小功能 关闭服务 软件白名单 应用控制 allowlisting',
    'cm-8': '资产盘点 资产清单 影子资产 asset inventory',
    'cp-2': '业务连续性 BCP 灾难恢复 DR 关键业务 RTO RPO continuity recovery',
    'cp-4': '灾难恢复演练 桌面演练 恢复验证 disaster recovery exercise',
    'cp-9': '不可变备份 备份隔离 勒索软件 数据恢复 immutable backup offline backup',
    'cp-10': '灾难恢复 恢复验证 系统重建 disaster recovery restore testing',
    'ia-2': '多因素认证 抗钓鱼 FIDO2 MFA phishing resistant authentication',
    'ia-3': '设备身份 设备认证 device authentication',
    'ia-5': '密码管理 凭据管理 凭据轮换 密钥保管 口令哈希 password hashing credential management secrets',
    'ia-10': '条件访问 风险认证 设备姿态 conditional access adaptive authentication',
    'ir-3': '事件响应演练 incident response exercise',
    'ir-4': '事件响应 安全事件 分析遏制 根除恢复 应急预案 incident response containment',
    'ir-5': '事件跟踪 安全事件工单 incident tracking',
    'ir-6': '事件通报 数据泄露通知 监管报告 受影响方通知 breach notification incident reporting',
    'ir-8': '事件响应预案 角色升级 取证沟通 incident response plan playbook',
    'mp-6': '介质销毁 数据安全删除 安全擦除 secure deletion media sanitization',
    'pe-3': '物理访问 门禁 机房 physical access',
    'pl-8': '安全架构 纵深防御 安全设计 security architecture defense in depth',
    'pm-9': '风险治理 风险容忍度 risk management strategy',
    'pm-12': '内部威胁 insider threat',
    'pm-23': '数据治理 数据所有者 data governance ownership',
    'ps-4': '离职撤权 离职账号 回收资产 termination offboarding',
    'ps-5': '转岗权限 权限累积 personnel transfer',
    'pt-2': '个人数据合法性 处理依据 lawful basis personal data',
    'pt-3': '目的限制 个人数据处理 数据最小化 purpose limitation data minimization',
    'pt-4': '个人信息 同意 consent privacy',
    'pt-5': '隐私通知 privacy notice',
    'ra-2': '数据分类分级 敏感度 信息分类 data classification',
    'ra-3': '风险评估 可能性 影响 风险负责人 risk assessment likelihood impact',
    'ra-5': '漏洞管理闭环 漏洞扫描 风险排序 修复时限 复测 vulnerability management remediation scanning',
    'ra-7': '风险处置 风险接受 限时例外 risk response exceptions',
    'ra-8': '数据保护影响评估 隐私风险 高风险个人数据处理 DPIA privacy impact assessment',
    'ra-10': '威胁狩猎 threat hunting',
    'sa-3': '安全开发 生命周期 SSDLC secure software development lifecycle',
    'sa-4': '供应商安全与隐私条款 合同 审计权 分包限制 supplier security privacy clauses contracts',
    'sa-9': '供应商安全与隐私条款 受托方 外包处理 云责任共担 共享责任 cloud shared responsibility external services',
    'sa-10': '版本控制 源码保护 source control configuration management',
    'sa-11': '代码安全测试 SAST DAST 自动化测试 developer security testing',
    'sa-15': '安全开发流水线 依赖扫描 软件成分分析 SCA SBOM dependency scanning',
    'sc-5': '拒绝服务 DDoS 流量清洗 rate limiting availability',
    'sc-7': '网络分段 零信任 网络访问控制 安全组最小暴露 防火墙 微隔离 network segmentation security groups least exposure',
    'sc-8': '传输加密 TLS HTTPS 通信完整性 encryption in transit',
    'sc-12': '密钥生命周期管理 密钥生成 轮换 吊销 HSM KMS cryptographic key lifecycle management',
    'sc-13': '密码技术 加密算法 cryptographic protection',
    'sc-17': '数字证书 PKI certificate management',
    'sc-20': 'DNS安全 DNSSEC authoritative name resolution',
    'sc-23': '会话管理 会话安全 认证cookie session management',
    'sc-28': '静态数据加密 全盘加密 磁盘加密 数据落盘 encryption at rest full disk encryption FDE',
    'sc-32': '系统分区 网络分段 微隔离 system partitioning',
    'sc-39': '进程隔离 容器隔离 process container isolation',
    'si-2': '漏洞管理闭环 补丁管理 资产关键性 可利用性 修复时限 复测 patch management flaw remediation',
    'si-3': '恶意软件防护 防病毒 杀毒 EPP malware protection',
    'si-4': '网络检测与响应 端点检测与响应 异常通信 罕见外部地址 EDR NDR network detection response monitoring',
    'si-7': '哈希 数字签名 完整性校验 篡改 来源认证 hash digital signature integrity verification',
    'si-8': '邮件安全 钓鱼邮件 反垃圾 SPF DKIM DMARC email security',
    'si-10': '输入校验 SQL注入 参数化查询 XSS 输出编码 CSRF 防护令牌 input validation injection',
    'si-12': '数据保留与安全销毁 保留期限 删除销毁 data retention secure disposal',
    'si-19': '令牌化 脱敏 匿名化 去标识化 tokenization masking de-identification',
    'sr-2': '第三方风险管理 供应链风险 third party supplier risk management',
    'sr-3': '供应链控制 分包限制 supply chain controls subcontractor',
    'sr-6': '供应商尽调 第三方风险评估 supplier due diligence assessment',
    'sr-8': '供应商事件通知 notification agreements',
}

def prose(part):
    return ' '.join([part.get('prose', '')] + [prose(p) for p in part.get('parts', [])]).strip()

def main():
    catalog = json.loads((ROOT/'tmp/nist_catalog.json').read_text(encoding='utf-8'))['catalog']
    rows = []
    for group in catalog['groups']:
        for control in group.get('controls', []):
            if any(p.get('name') == 'status' and p.get('value') == 'withdrawn' for p in control.get('props', [])):
                continue
            sections = [p for p in control.get('parts', []) if p.get('name') in {'statement', 'guidance'}]
            text = ' '.join(prose(p) for p in sections)
            text = re.sub(r'\{\{.*?\}\}', '[organization-defined parameter]', text)
            text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', text)
            rows.append({'id': control['id'], 'title': control['title'],
                         'aliases': ALIASES.get(control['id'], ''),
                         'text': text[:2600],
                         'source': 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'})
    target = ROOT/'attack_defense_bot/attack_defense_bot/knowledge/nist_controls.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({'source_catalog': 'https://github.com/usnistgov/oscal-content/tree/v1.4.0',
                                  'retrieved': '2026-10-28', 'documents': rows},ensure_ascii=False),encoding='utf-8')
    print('Built',len(rows),'source-based control documents;', target.stat().st_size,'bytes')

if __name__ == '__main__':
    main()
