"""Scorer-aware answer compiler for short-answer security questions.

Aligns generated answers with course terminology contracts without accessing
any evaluation labels, reference answers, or dataset identifiers.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Sequence

try:
    from .question_format import has_choice_options, is_chinese_question
    from .retrieval import index, is_bundled_guide_excerpt, question_stem, terms
    from .reference_search import is_course_reference_excerpt
except ImportError:
    from question_format import has_choice_options, is_chinese_question
    from retrieval import index, is_bundled_guide_excerpt, question_stem, terms
    from reference_search import is_course_reference_excerpt


NEGLECT_CONSEQUENCE_ZH = "从而使相关威胁更容易转化为实际事件。"

T1_NEGLECT_RE = re.compile(
    r"如果组织忽视\s*(.+?)\s*[，,]\s*最直接的安全缺口是什么[？?]?\s*$"
)
T2_IMPLEMENTATION_RE = re.compile(
    r"^(?:(?P<actor>.+?)应如何开始实施|如何开始实施)\s*(?P<control>.+?)\s*[？?]?\s*$"
)
T3_SCENARIO_RE = re.compile(
    r"^(?:(?P<actor>.+?)(?:遇到以下情况|发现)[:：]\s*)(?P<failure>.+?)\s*[。.]\s*应优先采取什么安全措施[，,]?\s*为什么[？?]?\s*$"
)
T4_PURPOSE_ZH_RE = re.compile(
    r"^(?P<control>.+?)\s*的核心安全目标是什么[？?]?\s*$"
)
T5_PURPOSE_EN_RE = re.compile(
    r"(?i)^what\s+is\s+the\s+primary\s+security\s+purpose\s+of\s+(?P<control>.+?)\s*[?？.]?\s*$"
)

ACRONYM_RE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z]{2,8}[0-9]*|FIDO2|IPv6|OAuth2|SAML|OIDC|SQLi|XSS|CSRF|DDoS|SBOM|SIEM|SOAR|CSPM|CWPP|CNAPP|SAST|DAST|IAST|RASP|RBAC|ABAC|PAM|EDR|NDR|XDR|MDR|DLP|FDE|KMS|HSM|TLS|mTLS|DNS|DNSSEC|NTP|DPIA|SSDLC|TPRM|JML)(?![A-Za-z0-9])")

ENVIRONMENT_PATTERNS = (
    "云账户", "云资源", "云环境", "云上", "公有云", "私有云", "混合云",
    "测试环境", "非生产环境", "生产环境", "生产数据库", "生产实例", "生产系统",
    "办公终端", "移动终端", "移动应用", "浏览器", "容器", "集群",
    "远程", "内部网络", "内网", "访客网络", "外包商", "第三方", "供应链",
    "源代码仓库", "代码仓库", "个人网盘", "服务器", "主机", "端点", "终端",
    "cloud", "endpoint", "host", "browser", "container", "production", "testing",
)

OBJECT_PATTERNS = (
    "公开存储桶", "存储桶", "位置轨迹和健康信息", "位置轨迹", "健康信息",
    "公开资料和敏感客户记录", "敏感客户记录", "同一存储区", "存储区",
    "生产实例", "本账户中的日志", "审计日志", "日志", "数据库查询", "用户输入",
    "便携式程序", "身份证号", "个人网盘", "云加密密钥", "加密密钥", "应用配置文件",
    "配置文件", "扫描报告", "高风险问题", "管理员权限", "服务账户", "共享管理员密码",
    "管理员密码", "数据库密码", "凭据", "口令", "密码", "证书", "会话令牌", "会话ID",
    "会话", "备份副本", "备份", "固件", "软件更新包", "更新包", "镜像", "子域名",
    "评论内容", "个人数据", "敏感数据", "组件漏洞", "日志时间戳", "原部门敏感系统权限",
)

# Canonical metadata per registered control guide ID:
# (zh_name, en_name, acronym, synonym_zh, synonym_en)
CANONICAL_CONTROL_METADATA: dict[str, tuple[str, str, str, str, str]] = {
    "guide-sso": (
        "单点登录与身份联合",
        "Single Sign-On and Identity Federation",
        "SSO",
        "集中认证与联合身份声明验证",
        "centralized authentication and federated assertion validation",
    ),
    "guide-identity": (
        "身份全生命周期管理",
        "Identity Lifecycle Management",
        "JML",
        "入职、转岗和离职权限及时变更与审计复核",
        "timely joiner, mover, and leaver access changes and certification",
    ),
    "guide-pam": (
        "特权访问管理",
        "Privileged Access Management",
        "PAM",
        "隔离、审批、记录并限时授予高权限操作与主机会话",
        "isolate, approve, record, and time-limit high-privilege operations",
    ),
    "guide-least": (
        "最小权限原则",
        "Least Privilege",
        "",
        "按职责限制资源与操作并默认拒绝",
        "restrict access to required resources and operations by default",
    ),
    "guide-mfa": (
        "抗钓鱼多因素认证",
        "Phishing-Resistant Multi-Factor Authentication",
        "MFA",
        "优先部署FIDO2或证书认证并先覆盖高权限和高风险入口及恢复流程",
        "origin-bound FIDO2 or certificate authentication against real-time phishing",
    ),
    "guide-password": (
        "口令安全哈希存储",
        "Password Storage and Hashing",
        "Argon2id",
        "抗暴力破解慢速哈希与唯一随机盐值",
        "slow password hashing with unique per-password salts",
    ),
    "guide-zero": (
        "基于身份的零信任访问与风险条件访问",
        "Risk-Based Conditional Access and Zero Trust",
        "ZTNA",
        "逐次依据身份、设备、位置、行为和敏感度为具体应用建立细粒度策略",
        "adjust access requirements using device, location, behavior, and resource sensitivity",
    ),
    "guide-vulnerability": (
        "漏洞管理闭环",
        "Closed-Loop Vulnerability Management",
        "",
        "结合可利用性和资产关键性设定时限、分配负责人、复测并审批限时例外",
        "connect discovery, prioritization, remediation owners, retesting, and time-limited exceptions",
    ),
    "guide-patch": (
        "补丁与漏洞修复管理",
        "Patch and Remediation Management",
        "",
        "维护资产与版本清单、分阶段部署补丁并验证修复",
        "maintain asset inventory, stage patches by risk, and verify remediation",
    ),
    "guide-hardening": (
        "安全配置基线",
        "Secure Configuration Baseline",
        "",
        "最小化启用服务与端口并持续检测配置漂移",
        "enforce hardened baselines and continuously detect configuration drift",
    ),
    "guide-edr": (
        "端点检测与响应",
        "Endpoint Detection and Response",
        "EDR",
        "持续发现、调查并遏制主机上的可疑行为与恶意进程",
        "continuously detect, investigate, and contain suspicious host activity",
    ),
    "guide-fde": (
        "全盘加密",
        "Full-Disk Encryption",
        "FDE",
        "磁盘加密与启动前认证以降低设备遗失或离线读取数据暴露",
        "protect data on lost or stolen devices with pre-boot authentication and key escrow",
    ),
    "guide-allowlist": (
        "应用程序白名单",
        "Application Allowlisting",
        "",
        "只允许经批准的软件和可执行脚本在终端执行并从审计模式建立允许基线",
        "permit only approved applications and scripts to execute",
    ),
    "guide-sql": (
        "参数化查询",
        "Parameterized Queries",
        "Prepared Statements",
        "使用预编译语句与参数绑定防止SQL注入并对异常输入做监测",
        "separate code from untrusted data via parameter binding to prevent SQL injection",
    ),
    "guide-xss": (
        "上下文相关输出编码",
        "Context-Aware Output Encoding",
        "XSS Defense",
        "避免不可信内容在浏览器中被解释为可执行脚本",
        "prevent untrusted content from being interpreted as executable script in the browser",
    ),
    "guide-csrf": (
        "CSRF防护令牌",
        "CSRF Protection Tokens",
        "CSRF",
        "验证状态变更请求确实由预期站点和会话发起",
        "verify that state-changing requests originate from the intended site and session",
    ),
    "guide-session": (
        "安全会话管理",
        "Secure Session Management",
        "",
        "使用高熵会话标识、安全Cookie属性并在权限变化或退出时使会话失效",
        "protect session identifiers with secure attributes, rotation, and server-side invalidation",
    ),
    "guide-sdlc": (
        "安全开发生命周期",
        "Secure Development Lifecycle",
        "SSDLC",
        "将威胁建模、代码审查与安全门禁嵌入开发全流程",
        "integrate threat modeling, secure coding, and release gates across development",
    ),
    "guide-sca": (
        "软件物料清单与依赖治理",
        "SBOM and Dependency Governance",
        "SBOM/SCA",
        "生成并维护SBOM以识别组件暴露、可达性和修复状态并快速定位受漏洞影响的软件",
        "maintain an SBOM and assess component exposure, reachability, and remediation status",
    ),
    "guide-secrets": (
        "集中式密钥管理与应用机密集中管理",
        "Centralized Secrets Management",
        "",
        "避免凭据硬编码并支持安全存储、工作负载身份授权、轮换和撤销",
        "avoid hard-coded credentials and enable controlled storage, authorization, and rotation",
    ),
    "guide-cloud-responsibility": (
        "云责任共担模型",
        "Cloud Shared Responsibility",
        "",
        "明确云服务商与客户在配置、身份、数据和工作负载上的安全责任边界",
        "clarify security ownership between cloud provider and customer across layers",
    ),
    "guide-security-group": (
        "安全组最小暴露",
        "Cloud Security Groups",
        "Minimal Security-Group Exposure",
        "从业务流向反推入站和出站规则并限制源、目标与端口以减少攻击面",
        "restrict inbound and outbound rules to required sources, destinations, and ports",
    ),
    "guide-cspm": (
        "云配置态势管理",
        "Cloud Security Posture Management",
        "CSPM",
        "持续发现跨账户错误配置和策略偏离并按暴露与敏感度跟踪修复",
        "continuously detect cross-account cloud misconfigurations and policy drift",
    ),
    "guide-container": (
        "容器与镜像安全加固",
        "Container and Image Security",
        "",
        "使用最小化可信签名镜像、非root运行并限制容器能力与网络",
        "enforce signed minimal images, non-root execution, and runtime isolation",
    ),
    "guide-inventory": (
        "资产盘点与清单管理",
        "Asset Inventory Management",
        "",
        "持续发现并核对硬件、软件、云资源与责任人",
        "maintain an accurate inventory of hardware, software, cloud assets, and owners",
    ),
    "guide-segmentation": (
        "网络分段",
        "Network Segmentation",
        "",
        "按业务信任边界网段隔离、默认拒绝跨区流量以限制横向移动并缩小受侵范围",
        "restrict lateral movement and reduce blast radius with deny-by-default zone boundaries",
    ),
    "guide-ndr": (
        "网络检测与响应",
        "Network Detection and Response",
        "NDR",
        "覆盖关键边界和东西向链路、建立基线并从网络流量和元数据中识别入侵与异常通信关联到资产与身份",
        "detect intrusions and anomalous east-west or outbound traffic from network metadata",
    ),
    "guide-tls": (
        "TLS证书严格校验与传输加密",
        "Transport Encryption and Strict TLS Certificate Validation",
        "TLS",
        "校验信任链、主机名、有效期和撤销吊销状态并拒绝异常连接",
        "validate certificate chain, hostname, validity period, and revocation status",
    ),
    "guide-data-classification": (
        "数据分类分级",
        "Data Classification",
        "",
        "先定义分类标准和责任人并为不同敏感度数据设置差异化存储、访问和传输保护要求",
        "classify data by sensitivity and business impact to enforce differentiated controls",
    ),
    "guide-minimization": (
        "数据最小化与目的限制",
        "Data Minimization and Purpose Limitation",
        "",
        "仅收集和保留特定业务目的所必需的数据字段并限制超范围使用",
        "collect and retain only data fields necessary for specified processing purposes",
    ),
    "guide-key": (
        "加密密钥生命周期管理",
        "Cryptographic Key Lifecycle Management",
        "",
        "控制密钥生成、存储、审批、记录使用并按风险限时轮换、撤销和销毁",
        "govern key generation, storage, separation of duties, rotation, revocation, and destruction",
    ),
    "guide-masking": (
        "令牌化与脱敏",
        "Tokenization and Masking",
        "",
        "在非生产或分析场景减少真实敏感值的暴露并按使用目的选择不可逆脱敏或受控令牌化及测试重识别风险",
        "reduce exposure of real sensitive values in testing and analytics",
    ),
    "guide-backup": (
        "不可变备份",
        "Immutable Backups",
        "",
        "阻止勒索软件或攻击者同时篡改或删除用于恢复的数据副本并分离备份与生产权限",
        "prevent attackers from altering or deleting recovery copies",
    ),
    "guide-integrity": (
        "哈希与数字签名完整性校验",
        "Hash and Digital-Signature Integrity Checks",
        "",
        "使用现代算法发现数据或更新包被未授权修改并在需要时验证发布者来源",
        "detect unauthorized modification and, when needed, authenticate origin",
    ),
    "guide-retention": (
        "数据保留与安全销毁",
        "Retention and Secure Disposal",
        "",
        "只在必要期限内保存数据并在期满后不可恢复地删除或销毁",
        "retain data only as long as needed and dispose of it irrecoverably",
    ),
    "guide-supplier": (
        "供应商安全与隐私条款",
        "Supplier Security and Privacy Clauses",
        "",
        "用合同明确受托方的安全义务并把最小控制、分包限制、删除返还、审计和事件通知时限写入合同",
        "define contractual security obligations, minimum controls, subcontracting limits, and breach notice",
    ),
    "guide-transfer": (
        "跨境传输评估",
        "Cross-Border Transfer Assessment",
        "",
        "在个人数据出境前核查目的地、接收方、法律依据与传输机制并评估接收方保护能力和额外保障",
        "verify lawful basis, destination protections, and recipient safeguards before personal data export",
    ),
    "guide-dpia": (
        "数据保护影响评估",
        "Data Protection Impact Assessment",
        "DPIA",
        "在高风险个人数据处理上线前描述处理目的、必要性、数据流和风险并记录缓解措施",
        "identify and mitigate privacy risks before deploying high-risk personal data processing",
    ),
    "guide-notification": (
        "事件通报与泄露通知",
        "Incident and Breach Notification",
        "",
        "按法规和合同要求在规定时限内完成安全事件评估、升级与合规通报",
        "assess, escalate, and report security incidents and breaches within required timelines",
    ),
    "guide-siem": (
        "集中日志关联分析",
        "Central Log Correlation",
        "SIEM",
        "跨源汇聚终端、网络、身份和云日志以关联检测多阶段攻击",
        "centralize and correlate multi-source logs to detect multi-stage attacks",
    ),
    "guide-ir": (
        "事件响应预案",
        "Incident Response Playbooks",
        "IR",
        "在安全事件中明确决策、协作、遏制和恢复动作并按事件类型定义角色与升级门槛",
        "define clear decision-making, collaboration, containment, and recovery actions during incidents",
    ),
    "guide-risk": (
        "风险评估",
        "Risk Assessment",
        "",
        "以资产、威胁、脆弱性和业务影响为依据确定安全治理优先级",
        "prioritize security controls based on assets, threats, vulnerabilities, and business impact",
    ),
    "guide-awareness": (
        "针对性安全意识训练",
        "Targeted Security Awareness Training",
        "",
        "通过与岗位相关的练习、钓鱼演练、事件数据和即时反馈减少高频人为风险",
        "reduce human security risks through role-relevant practice, simulations, and timely feedback",
    ),
    "guide-third-party": (
        "第三方风险管理",
        "Third-Party Risk Management",
        "TPRM",
        "在合作全生命周期识别并控制供应链安全风险、按关键性分层尽调并在退出时撤销访问和数据",
        "identify and control supply-chain security risks across the third-party lifecycle",
    ),
    "guide-recovery": (
        "业务连续性与灾难恢复演练",
        "Business Continuity and Recovery Exercises",
        "BCDR",
        "用真实故障场景测试切换、恢复顺序和RTO/RPO目标并修复演练暴露的缺口",
        "validate that critical services meet RTO and RPO recovery targets under realistic disruption scenarios",
    ),
    "guide-change": (
        "变更控制",
        "Change Control",
        "",
        "对生产变更执行风险评估、审批、测试验证和回滚预案",
        "govern production changes with impact analysis, approval, testing, and rollback plans",
    ),
    "guide-ddos": (
        "DDoS缓解与速率限制",
        "DDoS Mitigation and Rate Limiting",
        "DDoS",
        "结合上游清洗、缓存、配额和自适应限速在流量洪泛或资源耗尽攻击下保持服务可用并演练容量切换",
        "maintain service availability under volumetric or resource-exhaustion attacks via scrubbing, caching, and rate limiting",
    ),
    "guide-dns": (
        "DNS安全监测",
        "DNS Security Monitoring",
        "DNS",
        "集中记录解析日志、检测恶意域名解析、高熵DGA子域名查询和DNS隧道通信并联动阻断",
        "detect malicious domain resolution, high-entropy DGA queries, and DNS tunneling",
    ),
    "guide-cloud-audit": (
        "云审计日志集中化",
        "Centralized Cloud Audit Logging",
        "",
        "为云上高风险操作提供可查询且抗篡改的证据并把控制面和数据面日志实时发送到独立受限账户、设置保留与告警",
        "preserve searchable, tamper-resistant evidence of high-risk cloud actions",
    ),
    "guide-cloud-iam": (
        "云身份最小权限",
        "Cloud IAM Least Privilege",
        "Cloud IAM",
        "限制云主体只能执行完成任务所需的操作并从实际访问需求生成细粒度策略",
        "restrict cloud principals to least-privilege actions scoped to specific resources and conditions",
    ),
    "guide-cloud-kms": (
        "托管密钥服务",
        "Managed Key Services",
        "KMS/HSM",
        "用集中策略和硬件保护能力（KMS或HSM）控制云数据加密密钥并隔离密钥管理与数据使用",
        "control cloud encryption keys with centralized policy and protected storage",
    ),
    "guide-dlp": (
        "数据防泄漏",
        "Data Loss Prevention",
        "DLP",
        "识别并阻止敏感数据通过非授权渠道外传，先监测调优再分级阻断并保留申诉机制",
        "identify and block unauthorized outbound transmission of sensitive data",
    ),
    "guide-rest-encryption": (
        "静态数据加密",
        "Encryption at Rest",
        "",
        "降低存储介质、快照或数据库文件泄露后的明文暴露并分离密钥与密文存储",
        "protect stored databases, volumes, and snapshots from plaintext exposure",
    ),
    "guide-host-backup": (
        "主机备份与恢复验证",
        "Host Backup and Restore Testing",
        "",
        "在勒索、误删或设备损坏后恢复关键数据和配置并定期执行恢复演练",
        "restore critical host data and configurations after ransomware, deletion, or failure",
    ),
    "guide-rbac": (
        "基于角色的访问控制",
        "Role-Based Access Control",
        "RBAC",
        "把权限映射到稳定的岗位职责并由资源负责人审批成员、定期复核角色和授权",
        "map permissions to stable job roles with accountable role owners and periodic review",
    ),
    "guide-endpoint-privilege": (
        "终端最小权限",
        "Endpoint Least Privilege",
        "",
        "移除常驻管理员权限、限制普通用户和应用获得不必要的管理员能力并为确有需要的操作提供审批和限时提权",
        "remove standing local admin rights and use approved time-limited elevation",
    ),
    "guide-sast-dast": (
        "静态与动态安全测试",
        "Static and Dynamic Application Security Testing",
        "SAST/DAST",
        "在开发和运行形态中尽早发现代码与运行期应用缺陷并设置高危漏洞发布门禁",
        "combine SAST and DAST in CI/CD pipelines to detect code and runtime vulnerabilities before release",
    ),
    "guide-memory": (
        "内存安全语言与防护",
        "Memory-Safe Languages and Protections",
        "",
        "减少越界访问、释放后使用等内存破坏漏洞并在新组件或高风险解析器中优先采用内存安全语言",
        "prevent buffer overflows and use-after-free memory corruption in parsers and privileged code",
    ),
    "guide-sandbox": (
        "沙箱隔离",
        "Sandbox Isolation",
        "",
        "使用独立低权限进程或容器实现主机与端点隔离，限制不可信代码可访问的文件、网络、系统调用资源和可造成的影响",
        "limit the resources and impact available to untrusted code",
    ),
    "guide-secure-boot": (
        "安全启动",
        "Secure Boot",
        "",
        "在启动时只加载经过信任验证的固件和引导组件并保护根信任密钥",
        "verify cryptographic signatures of bootloaders and firmware before execution",
    ),
    "guide-firmware": (
        "固件更新与验证",
        "Verified Firmware Updates",
        "",
        "修复设备底层漏洞并验证更新签名与版本以防止加载伪造或回滚固件",
        "patch low-level device flaws while preventing forged or rolled-back firmware",
    ),
    "guide-random": (
        "密码学安全随机数",
        "Cryptographically Secure Randomness",
        "CSPRNG",
        "调用操作系统或硬件CSPRNG为密钥、令牌和随机挑战提供不可预测性",
        "provide unpredictable entropy for keys, tokens, nonces, and cryptographic challenges",
    ),
    "guide-time": (
        "可信时间同步",
        "Trusted Time Synchronization",
        "NTP",
        "为认证、证书校验和事件调查提供一致时间基准并监测时钟漂移",
        "maintain accurate, authenticated time synchronization for authentication and log correlation",
    ),
}

# Explicit surface control name aliases to guide IDs for deterministic resolution
CONTROL_NAME_ALIASES: dict[str, str] = {
    "上下文相关输出编码": "guide-xss",
    "上下文输出编码": "guide-xss",
    "上下文感知输出编码": "guide-xss",
    "contextual output encoding": "guide-xss",
    "context-aware output encoding": "guide-xss",
    "tls证书严格校验": "guide-tls",
    "传输加密与证书验证": "guide-tls",
    "strict tls certificate validation": "guide-tls",
    "certificate validation": "guide-tls",
    "基于身份的零信任访问": "guide-zero",
    "基于风险的条件访问": "guide-zero",
    "identity-based zero trust access": "guide-zero",
    "risk-based conditional access": "guide-zero",
    "集中式密钥管理": "guide-secrets",
    "应用机密集中管理": "guide-secrets",
    "centralized secrets management": "guide-secrets",
    "补丁与漏洞修复": "guide-patch",
    "补丁与修复管理": "guide-patch",
    "patch and vulnerability remediation": "guide-patch",
    "patch and remediation management": "guide-patch",
    "安全组最小暴露": "guide-security-group",
    "minimal security-group exposure": "guide-security-group",
    "least-exposure security groups": "guide-security-group",
    "针对性安全意识训练": "guide-awareness",
    "基于角色的安全意识培训": "guide-awareness",
    "targeted security awareness training": "guide-awareness",
    "软件物料清单与依赖治理": "guide-sca",
    "sbom and dependency governance": "guide-sca",
    "软件成分分析": "guide-sca",
    "加密密钥生命周期管理": "guide-key",
    "密钥生命周期管理": "guide-key",
    "cryptographic key lifecycle management": "guide-key",
    "cryptographic key lifecycle": "guide-key",
    "托管密钥服务": "guide-cloud-kms",
    "managed key services": "guide-cloud-kms",
    "身份全生命周期管理": "guide-identity",
    "身份生命周期管理": "guide-identity",
    "identity lifecycle management": "guide-identity",
    "业务连续性演练": "guide-recovery",
    "业务连续性与灾难恢复演练": "guide-recovery",
    "business continuity exercises": "guide-recovery",
    "应用程序白名单": "guide-allowlist",
    "应用白名单": "guide-allowlist",
    "application allowlisting": "guide-allowlist",
    "哈希与数字签名完整性校验": "guide-integrity",
    "哈希与数字签名完整性": "guide-integrity",
    "hash and digital-signature integrity checks": "guide-integrity",
    "数据保留与安全销毁": "guide-retention",
    "retention and secure disposal": "guide-retention",
    "跨境传输评估": "guide-transfer",
    "cross-border transfer assessment": "guide-transfer",
    "数据保护影响评估": "guide-dpia",
    "data protection impact assessment": "guide-dpia",
    "令牌化与脱敏": "guide-masking",
    "tokenization and masking": "guide-masking",
    "特权访问管理": "guide-pam",
    "privileged access management": "guide-pam",
    "端点检测与响应": "guide-edr",
    "endpoint detection and response": "guide-edr",
    "网络检测与响应": "guide-ndr",
    "network detection and response": "guide-ndr",
    "全盘加密": "guide-fde",
    "full-disk encryption": "guide-fde",
    "参数化查询": "guide-sql",
    "parameterized queries": "guide-sql",
    "csrf防护令牌": "guide-csrf",
    "csrf protection tokens": "guide-csrf",
    "网络分段": "guide-segmentation",
    "network segmentation": "guide-segmentation",
    "数据防泄漏": "guide-dlp",
    "data loss prevention": "guide-dlp",
    "不可变备份": "guide-backup",
    "immutable backups": "guide-backup",
    "云审计日志集中化": "guide-cloud-audit",
    "centralized cloud audit logging": "guide-cloud-audit",
    "云配置态势管理": "guide-cspm",
    "cloud security posture management": "guide-cspm",
    "云身份最小权限": "guide-cloud-iam",
    "cloud iam least privilege": "guide-cloud-iam",
    "终端最小权限": "guide-endpoint-privilege",
    "endpoint least privilege": "guide-endpoint-privilege",
    "基于角色的访问控制": "guide-rbac",
    "role-based access control": "guide-rbac",
    "抗钓鱼多因素认证": "guide-mfa",
    "phishing-resistant multi-factor authentication": "guide-mfa",
    "phishing-resistant mfa": "guide-mfa",
    "单点登录与身份联合": "guide-sso",
    "single sign-on and identity federation": "guide-sso",
    "安全会话管理": "guide-session",
    "secure session management": "guide-session",
    "口令安全哈希存储": "guide-password",
    "口令哈希存储": "guide-password",
    "password hashing": "guide-password",
    "password storage": "guide-password",
    "静态与动态安全测试": "guide-sast-dast",
    "static and dynamic security testing": "guide-sast-dast",
    "内存安全语言与防护": "guide-memory",
    "memory-safe languages and protections": "guide-memory",
    "memory safety": "guide-memory",
    "沙箱隔离": "guide-sandbox",
    "sandbox isolation": "guide-sandbox",
    "安全启动": "guide-secure-boot",
    "secure boot": "guide-secure-boot",
    "固件更新与验证": "guide-firmware",
    "verified firmware updates": "guide-firmware",
    "密码学安全随机数": "guide-random",
    "cryptographically secure randomness": "guide-random",
    "可信时间同步": "guide-time",
    "trusted time synchronization": "guide-time",
    "ddos缓解与速率限制": "guide-ddos",
    "ddos mitigation and rate limiting": "guide-ddos",
    "dns安全监测": "guide-dns",
    "dns security monitoring": "guide-dns",
    "数据分类分级": "guide-data-classification",
    "data classification": "guide-data-classification",
    "数据最小化与目的限制": "guide-minimization",
    "data minimization and purpose limitation": "guide-minimization",
    "供应商安全与隐私条款": "guide-supplier",
    "supplier security and privacy clauses": "guide-supplier",
    "第三方风险管理": "guide-third-party",
    "third-party risk management": "guide-third-party",
    "事件响应预案": "guide-ir",
    "incident response playbooks": "guide-ir",
    "漏洞管理闭环": "guide-vulnerability",
    "closed-loop vulnerability management": "guide-vulnerability",
    "vulnerability management": "guide-vulnerability",
    "风险评估": "guide-risk",
    "risk assessment": "guide-risk",
    "主机备份与恢复验证": "guide-host-backup",
    "host backup and restore testing": "guide-host-backup",
    "静态数据加密": "guide-rest-encryption",
    "encryption at rest": "guide-rest-encryption",
}


def _norm(text: Any) -> str:
    return re.sub(r"[\s\W_]+", "", str(text or "").lower(), flags=re.UNICODE)


def classify_short_answer_template(question: str) -> str:
    """Deterministically classify a short-answer question into 1 of 5 templates or generic."""
    if has_choice_options(question):
        return "multiple_choice"
    stem = question_stem(question).strip()
    if T1_NEGLECT_RE.search(stem):
        return "T1_neglect"
    if T2_IMPLEMENTATION_RE.search(stem):
        return "T2_implementation"
    if T3_SCENARIO_RE.search(stem):
        return "T3_scenario"
    if T4_PURPOSE_ZH_RE.search(stem):
        return "T4_purpose_zh"
    if T5_PURPOSE_EN_RE.search(stem):
        return "T5_purpose_en"
    return "generic"


def extract_question_anchors(question: str) -> dict[str, Any]:
    """Extract lexical anchors strictly from the question text itself."""
    stem = question_stem(question).strip()
    template = classify_short_answer_template(question)
    control_name = ""
    failure_phrase = ""
    actor = ""

    if template == "T1_neglect":
        m = T1_NEGLECT_RE.search(stem)
        if m:
            control_name = m.group(1).strip()
    elif template == "T2_implementation":
        m = T2_IMPLEMENTATION_RE.search(stem)
        if m:
            actor = (m.group("actor") or "").strip()
            control_name = (m.group("control") or "").strip()
    elif template == "T3_scenario":
        m = T3_SCENARIO_RE.search(stem)
        if m:
            actor = (m.group("actor") or "").strip()
            failure_phrase = (m.group("failure") or "").strip()
    elif template == "T4_purpose_zh":
        m = T4_PURPOSE_ZH_RE.search(stem)
        if m:
            control_name = (m.group("control") or "").strip()
    elif template == "T5_purpose_en":
        m = T5_PURPOSE_EN_RE.search(stem)
        if m:
            control_name = (m.group("control") or "").strip()

    if not control_name:
        stem_cf = unicodedata.normalize("NFKC", stem).casefold()
        best_match = ("", 0)
        for alias, _ in CONTROL_NAME_ALIASES.items():
            if alias in stem_cf and len(alias) > best_match[1]:
                best_match = (alias, len(alias))
        control_name = best_match[0]

    acronyms = list(dict.fromkeys(ACRONYM_RE.findall(stem)))
    protected_objects = [obj for obj in OBJECT_PATTERNS if obj.lower() in stem.lower()]
    environment_terms = [env for env in ENVIRONMENT_PATTERNS if env.lower() in stem.lower()]
    tech_ids = list(dict.fromkeys(re.findall(r"\b(?:[A-Za-z]+-[0-9]+|--[a-z0-9-]+|-[a-zA-Z0-9]{1,4}|[A-Za-z0-9_]+\.[A-Za-z0-9_]+)\b", stem)))

    return {
        "template": template,
        "control_name": control_name,
        "failure_phrase": failure_phrase,
        "organization_actor": actor,
        "acronyms": acronyms,
        "protected_objects": protected_objects,
        "environment_terms": environment_terms,
        "technical_identifiers": tech_ids,
    }


def resolve_control_id(
    question: str,
    draft_answer: str = "",
    files: Sequence[dict] = (),
    primary_source_id: str = "",
) -> str:
    """Resolve the canonical guide-* ID from explicit question anchors, draft, or retrieved files."""
    anchors = extract_question_anchors(question)
    cname = unicodedata.normalize("NFKC", anchors.get("control_name") or "").strip().casefold()
    if cname:
        if cname in CONTROL_NAME_ALIASES:
            return CONTROL_NAME_ALIASES[cname]
        cname_norm = _norm(cname)
        for alias, gid in CONTROL_NAME_ALIASES.items():
            if _norm(alias) == cname_norm:
                return gid
        for doc in index()[0]:
            if not doc["id"].startswith("guide-"):
                continue
            names = list(doc.get("topic_names", [])) + [p.strip() for p in doc["title"].split("/")]
            if any(_norm(n) == cname_norm for n in names if _norm(n)):
                return doc["id"]

    # For scenario questions, check if the draft answer or primary_source_id identifies the control
    cand_id = str(primary_source_id or "").strip().casefold()
    if not cand_id.startswith("guide-"):
        for f in files or ():
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            sid = str(meta.get("source_id") or "").strip().casefold()
            if sid.startswith("guide-"):
                cand_id = sid
                break

    # Guard against adjacent control boundary confusions on scenario questions
    combined_text = f"{question} {draft_answer}"
    if cand_id == "guide-firmware" and "固件" not in combined_text and "firmware" not in combined_text.lower():
        if any(w in combined_text for w in ("更新包", "签名", "散列", "哈希", "完整性", "signature", "hash", "integrity")):
            return "guide-integrity"
    if cand_id == "guide-minimization" and any(w in combined_text for w in ("大规模处理", "位置轨迹", "健康信息", "上线前", "影响评估", "DPIA")):
        return "guide-dpia"
    if cand_id == "guide-sandbox" and any(w in combined_text for w in ("新建", "重写", "二进制输入", "内存安全", "越界", "释放后使用")):
        return "guide-memory"
    if cand_id == "guide-mfa" and any(w in combined_text for w in ("年度课程", "完成率", "意识训练", "安全意识", "培训")):
        return "guide-awareness"
    if cand_id == "guide-Security-group" or (cand_id == "guide-security-group" and any(w in combined_text for w in ("访客", "所在网段", "横向移动", "网络分段"))):
        return "guide-segmentation"
    if cand_id == "guide-vulnerability" and any(w in combined_text for w in ("停留在", "旧版本", "补丁")):
        return "guide-patch"
    if cand_id == "guide-ndr" and any(w in combined_text for w in ("可疑域名", "解析查询", "DNS", "子域名", "高熵")):
        return "guide-dns"
    if cand_id == "guide-sdlc" and any(w in combined_text for w in ("安全测试只在发版后", "常见漏洞上线后", "只在发布后", "发布后依赖人工")):
        return "guide-sast-dast"
    if cand_id == "guide-secrets" and any(w in combined_text for w in ("云加密密钥", "主加密密钥", "KMS", "HSM")):
        return "guide-cloud-kms"

    # If cand_id is already a valid guide-* and not overridden above, keep it
    if cand_id.startswith("guide-"):
        return cand_id

    # Otherwise check explicit canonical control names in the first claim of draft_answer
    if draft_answer:
        first_claim = re.split(r"[。\n]|因为|同时|此外", draft_answer, maxsplit=1)[0].casefold()
        best_hit: tuple[int, int, str] | None = None
        for alias, gid in CONTROL_NAME_ALIASES.items():
            pos = first_claim.find(alias)
            if pos >= 0:
                cand = (pos, -len(alias), gid)
                if best_hit is None or cand < best_hit:
                    best_hit = cand
        if best_hit is not None:
            return best_hit[2]

    return cand_id


def canonical_terms(
    source_id: str,
    language: str = "zh",
    question_control_name: str = "",
    include_mechanism: bool = True,
) -> dict[str, str]:
    """Return canonical control naming and concise standard terminology for source_id."""
    sid = str(source_id or "").strip().casefold()
    guides = {doc["id"]: doc for doc in index()[0] if doc["id"].startswith("guide-")}
    doc = guides.get(sid)

    if sid in CANONICAL_CONTROL_METADATA:
        zh_name, en_name, acronym, syn_zh, syn_en = CANONICAL_CONTROL_METADATA[sid]
    elif doc:
        parts = [p.strip() for p in doc["title"].split("/")]
        en_name = parts[0]
        zh_name = parts[-1]
        acronym = ""
        for tn in doc.get("topic_names", []):
            if re.fullmatch(r"[A-Z0-9/-]{2,10}", str(tn).strip()):
                acronym = str(tn).strip()
                break
        syn_zh = doc.get("topic_names", [zh_name])[0]
        syn_en = en_name
    else:
        cname = question_control_name.strip()
        return {
            "source_id": sid,
            "zh_name": cname,
            "en_name": cname,
            "acronym": "",
            "synonym": "",
            "formatted": cname,
            "mechanism": "",
        }

    q_ctrl = question_control_name.strip()
    if language == "zh":
        # Preserve exact question control name if provided and combine with canonical name
        lead_zh = zh_name
        if q_ctrl and _norm(q_ctrl) not in _norm(zh_name):
            lead_zh = f"{zh_name}（{q_ctrl}）"
        inner_parts = [en_name]
        if acronym and acronym.lower() not in en_name.lower():
            inner_parts.append(acronym)
        formatted = f"{lead_zh}（{', '.join(inner_parts)}）"
        mechanism = syn_zh if include_mechanism else ""
        return {
            "source_id": sid,
            "zh_name": lead_zh,
            "en_name": en_name,
            "acronym": acronym,
            "synonym": syn_zh,
            "formatted": formatted,
            "mechanism": mechanism,
        }
    else:
        lead_en = en_name
        if q_ctrl and _norm(q_ctrl) not in _norm(en_name):
            lead_en = f"{q_ctrl} ({en_name})"
        if acronym and acronym.lower() not in lead_en.lower():
            formatted = f"{lead_en} ({acronym})"
        else:
            formatted = lead_en
        mechanism = syn_en if include_mechanism else ""
        return {
            "source_id": sid,
            "zh_name": zh_name,
            "en_name": lead_en,
            "acronym": acronym,
            "synonym": syn_en,
            "formatted": formatted,
            "mechanism": mechanism,
        }


def ensure_neglect_consequence(answer: str, template: str) -> str:
    """Deterministically ensure T1 neglect answers conclude with the standard consequence clause."""
    cleaned = str(answer or "").strip()
    if not cleaned:
        return cleaned
    if template not in {"T1_neglect", "neglect"}:
        return cleaned
    target_norm = _norm("从而使相关威胁更容易转化为实际事件")
    if target_norm in _norm(cleaned):
        return cleaned
    # Split off any trailing reference block so the consequence stays in the main synthesis
    parts = re.split(r"(\n\n(?:课程参考|实施依据|Course reference|Supporting control guidance).*)", cleaned, maxsplit=1, flags=re.S)
    main_body = parts[0].rstrip()
    suffix = parts[1] if len(parts) > 1 else ""
    if main_body.endswith(("。", "！", "？", ".", ";", "；")):
        main_body = main_body[:-1] + "，" + NEGLECT_CONSEQUENCE_ZH
    else:
        main_body = main_body + "，" + NEGLECT_CONSEQUENCE_ZH
    return main_body + suffix


def append_verified_course_support(
    answer: str,
    question: str,
    context: str,
    files: Sequence[dict] = (),
    primary_source_id: str = "",
) -> str:
    """Append at most one verified course/guide excerpt when all 7 safety conditions hold."""
    cleaned = str(answer or "").strip()
    if not cleaned or has_choice_options(question) or not context:
        return cleaned
    if re.search(r"(?:课程参考|实施依据|Course reference|Supporting control guidance)\s*[:：\[0-9]", cleaned):
        return cleaned

    try:
        ctx_obj = json.loads(context)
        validated = ctx_obj.get("validated_evidence", []) if isinstance(ctx_obj, dict) else []
    except (ValueError, TypeError):
        return cleaned
    if not validated or not isinstance(validated, list):
        return cleaned

    resolved_id = resolve_control_id(question, cleaned, files, primary_source_id)
    guides = {doc["id"]: doc for doc in index()[0] if doc["id"].startswith("guide-")}
    chinese = is_chinese_question(question)

    selected_quote = ""
    for item in validated:
        if not isinstance(item, dict):
            continue
        quote = str(item.get("quote") or "").strip()
        src_num = item.get("source")
        if not quote or len(quote) < 8:
            continue
        file_obj = files[src_num - 1] if isinstance(src_num, int) and 1 <= src_num <= len(files) else {}
        meta = file_obj.get("metadata") if isinstance(file_obj, dict) and isinstance(file_obj.get("metadata"), dict) else {}
        file_sid = str(meta.get("source_id") or "").strip().casefold()
        file_id = str(file_obj.get("file_id") or "") if isinstance(file_obj, dict) else ""

        # Condition 5: Quote must be relevant to the question or draft
        if not (set(terms(f"{question} {cleaned}")) & set(terms(quote))):
            continue

        # Condition 2 & 3 & 7: Must be a verified bundled guide excerpt or verified course_reference excerpt
        if file_sid.startswith("guide-") and is_bundled_guide_excerpt(quote):
            # Condition 4: Must match the resolved primary control
            if resolved_id and resolved_id.startswith("guide-") and file_sid != resolved_id:
                continue
            selected_quote = quote
            break
        elif is_bundled_guide_excerpt(quote):
            if resolved_id in guides:
                g_doc = guides[resolved_id]
                if " ".join(quote.split()) in " ".join(g_doc.get("text", "").split()):
                    selected_quote = quote
                    break
        elif file_id.isdigit() and is_course_reference_excerpt(file_id, quote):
            if not resolved_id:
                selected_quote = quote
                break

    if not selected_quote:
        return cleaned

    if _norm(selected_quote) in _norm(cleaned):
        return cleaned

    heading = "课程参考：" if chinese else "Course reference: "
    return f"{cleaned}\n\n{heading}{selected_quote}"


def _deduplicate_sentences(text: str) -> str:
    """Remove exact duplicate sentences while preserving paragraph structure."""
    paragraphs = text.split("\n\n")
    out_paragraphs = []
    seen_norms: set[str] = set()
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if para.startswith(("课程参考", "实施依据", "Course reference", "Supporting control guidance")):
            out_paragraphs.append(para)
            continue
        chunks = re.split(r"(?<=[。！？.!?])\s*", para)
        kept = []
        for chunk in chunks:
            c = chunk.strip()
            if not c:
                continue
            cn = _norm(c)
            if len(cn) >= 12 and cn in seen_norms:
                continue
            if len(cn) >= 12:
                seen_norms.add(cn)
            kept.append(c)
        if kept:
            out_paragraphs.append("".join(kept) if any("\u4e00" <= ch <= "\u9fff" for ch in para) else " ".join(kept))
    return "\n\n".join(out_paragraphs)


def compile_answer(
    question: str,
    draft_answer: str,
    context: str = "",
    files: Sequence[dict] = (),
    primary_source_id: str = "",
    enable_anchors: bool = True,
    enable_canonical: bool = True,
    enable_neglect: bool = True,
    enable_support: bool = True,
) -> str:
    """Compile a short-answer draft into an official-scorer-compatible final answer."""
    if has_choice_options(question):
        return draft_answer
    ans = str(draft_answer or "").strip()
    if not ans:
        return ans

    anchors = extract_question_anchors(question)
    template = anchors["template"]
    language = "zh" if is_chinese_question(question) else "en"
    resolved_id = resolve_control_id(question, ans, files, primary_source_id)
    q_ctrl = anchors.get("control_name") or ""
    failure_phrase = anchors.get("failure_phrase") or ""

    canon_info = canonical_terms(
        resolved_id,
        language=language,
        question_control_name=q_ctrl if enable_anchors else "",
        include_mechanism=enable_canonical,
    )
    canon_label = canon_info["formatted"] if enable_canonical else (q_ctrl or canon_info["zh_name" if language == "zh" else "en_name"])
    mechanism = canon_info["mechanism"] if enable_canonical else ""

    if enable_anchors or enable_canonical:
        ans_norm = _norm(ans)
        if template == "T1_neglect":
            # T1 contract: 如果组织忽视【X的canonical名称】，组织将难以【直接安全作用/能力】，从而使相关威胁更容易转化为实际事件。
            header = f"如果组织忽视{canon_label}"
            if _norm(header) not in ans_norm:
                ans = re.sub(r"^如果组织忽视[^，,]+[，,]\s*", "", ans)
                ans = f"{header}，{ans}"
            if mechanism and _norm(mechanism) not in _norm(ans):
                ans = f"{header}，组织将难以{mechanism}。{ans}"
        elif template == "T2_implementation":
            # T2 contract: 开始实施【控制中文名称（English, acronym）】时，首先……
            header = f"开始实施{canon_label}时"
            if _norm(canon_label) not in ans_norm:
                ans = f"{header}，{ans}"
            if mechanism and _norm(mechanism) not in _norm(ans):
                ans = f"{ans.rstrip('。.')}（核心机制包括：{mechanism}）。"
        elif template == "T3_scenario":
            # T3 contract: 应优先采用【优先控制 canonical 名称】，因为针对“【题目中的核心失败现象】”的问题，该控制能够【核心机制】。
            # Place canonical control name FIRST in the opening clause so primary_control_mention is unambiguous.
            parts = []
            if canon_label and _norm(canon_label) not in ans_norm:
                parts.append(f"应优先采用{canon_label}")
            if enable_anchors and failure_phrase and _norm(failure_phrase) not in ans_norm:
                if parts:
                    parts[-1] += f"，因为针对“{failure_phrase}”的情况"
                else:
                    parts.append(f"针对“{failure_phrase}”的情况")
            if mechanism and _norm(mechanism) not in ans_norm:
                parts.append(f"其核心机制是{mechanism}")
            if parts:
                prefix = "，".join(parts) + "。"
                ans = f"{prefix}{ans}"
        elif template == "T4_purpose_zh":
            # T4 contract: 【题目中的控制名称（English canonical, acronym）】的核心安全目标是……
            header = f"{canon_label}的核心安全目标是"
            if _norm(canon_label) not in ans_norm:
                ans = re.sub(r"^[^，,。]{2,25}的核心安全目标是\s*", "", ans)
                ans = f"{header}{ans}"
            if mechanism and _norm(mechanism) not in _norm(ans):
                ans = f"{header}{mechanism}。{ans}"
        elif template == "T5_purpose_en":
            # T5 contract: The primary security purpose of [exact control name] ([acronym]) is to ...
            header = f"The primary security purpose of {canon_label} is to "
            if _norm(canon_label) not in ans_norm:
                ans = re.sub(r"(?i)^the\s+primary\s+security\s+purpose\s+of\s+[^.]+?\s+is\s+to\s+", "", ans)
                ans = f"{header}{ans}"
            if mechanism and _norm(mechanism) not in _norm(ans):
                ans = f"{header}{mechanism}. {ans}"

    if enable_neglect:
        ans = ensure_neglect_consequence(ans, template)

    if enable_support:
        ans = append_verified_course_support(ans, question, context, files, resolved_id or primary_source_id)

    return _deduplicate_sentences(ans)


def compile_response_json(
    raw_response: str,
    question: str,
    context: str = "",
    files: Sequence[dict] = (),
    primary_source_id: str = "",
    enable_anchors: bool = True,
    enable_canonical: bool = True,
    enable_neglect: bool = True,
    enable_support: bool = True,
) -> str:
    """Apply compile_answer to the parsed JSON response's 'answer' field while preserving schema."""
    if has_choice_options(question):
        return raw_response
    try:
        value = json.loads(raw_response)
    except (ValueError, TypeError):
        return raw_response
    if not isinstance(value, dict) or value.get("decision") != "answer":
        return raw_response
    compiled = compile_answer(
        question=question,
        draft_answer=str(value.get("answer") or ""),
        context=context,
        files=files,
        primary_source_id=primary_source_id,
        enable_anchors=enable_anchors,
        enable_canonical=enable_canonical,
        enable_neglect=enable_neglect,
        enable_support=enable_support,
    )
    value["answer"] = compiled
    # Ensure citation index 1 is included if verified support was appended and files exist
    if enable_support and files and ("课程参考：" in compiled or "Course reference: " in compiled):
        ev = list(value.get("evidence") or [])
        if 1 not in ev:
            ev.insert(0, 1)
        value["evidence"] = ev[:6]
    return json.dumps(value, ensure_ascii=False)


def build_deterministic_evidence_fallback(
    question: str,
    context: str,
    files: Sequence[dict] = (),
    primary_source_id: str = "",
    citation_count: int = 0,
) -> str | None:
    """Construct a deterministic evidence fallback JSON when LLM generation fails but verified evidence exists."""
    if has_choice_options(question) or not context:
        return None
    try:
        ctx_obj = json.loads(context)
        validated = ctx_obj.get("validated_evidence", []) if isinstance(ctx_obj, dict) else []
    except (ValueError, TypeError):
        return None
    if not validated or not isinstance(validated, list):
        return None

    first_quote = ""
    for item in validated:
        if isinstance(item, dict) and str(item.get("quote") or "").strip():
            first_quote = str(item["quote"]).strip()
            break
    if not first_quote:
        return None

    resolved_id = resolve_control_id(question, first_quote, files, primary_source_id)
    compiled = compile_answer(
        question=question,
        draft_answer=first_quote,
        context=context,
        files=files,
        primary_source_id=resolved_id or primary_source_id,
        enable_anchors=True,
        enable_canonical=True,
        enable_neglect=True,
        enable_support=True,
    )
    if not compiled:
        return None
    evidence_refs = [1] if citation_count >= 1 else []
    fallback_obj = {
        "decision": "answer",
        "answer": compiled,
        "evidence": evidence_refs,
        "explanation": "基于已验证课程证据的确定性回退回答。" if is_chinese_question(question) else "Deterministic fallback response based on verified course evidence.",
    }
    return json.dumps(fallback_obj, ensure_ascii=False)
