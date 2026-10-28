"""Add source-derived retrieval descriptions, never sample questions/labels."""
import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
contexts={
 'guide-retention':(
  '适用范围：个人信息、身份材料、业务文件和历史记录的保留期限、处理目的完成、项目结束、数据过期、不再需要以及安全删除或介质销毁；处理保存的数据记录而非人员账户权限。 Scope: records retention, obsolete documents, completed business purpose, expired personal data and verified secure disposal.',
  'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final#SI-12'),
 'guide-zero':(
  '适用范围：远程接入、VPN或内部网络位置不能自动授予信任；对具体应用和资源按身份、设备健康、行为、位置及上下文逐次验证和授权。 Scope: remote access, VPN implicit trust, per-resource authorization, continuous identity and device verification.',
  'https://csrc.nist.gov/pubs/sp/800/207/final'),
 'guide-memory':(
  '适用范围：新建或重写解析器、处理不可信二进制输入的高权限服务、越界读写、释放后使用和内存破坏。通过内存安全语言与边界检查预防实现缺陷，隔离作为补充。 Scope: new parser implementation, untrusted binary input, privileged services, bounds safety, use-after-free and memory corruption prevention.',
  'https://www.cisa.gov/sites/default/files/2023-12/The-Case-for-Memory-Safe-Roadmaps-508c.pdf'),
 'guide-patch':(
  '适用范围：终端或服务器已部署软件的旧版本、已知漏洞、远程代码执行缺陷与安全更新；按风险安排测试、升级、补丁分发及修复验证。 Scope: outdated deployed software, known exploitable vulnerabilities, security updates, staged patch deployment and verification.',
  'https://csrc.nist.gov/pubs/sp/800/40/r4/final'),
 'guide-fde':(
  '适用范围：笔记本、手提电脑、移动终端和可移动存储在遗失、丢失、被盗、失窃或离线读取时的存储保密。保护静态数据，配合恢复密钥托管和启动前认证。 Scope: laptop, notebook, portable device, lost or stolen computer, offline disk access and removable storage confidentiality.',
  'https://csrc.nist.gov/pubs/sp/800/111/final'),
 'guide-dlp':(
  '适用范围：敏感文件、个人信息、身份标识和表格在终端、邮件、浏览器及云服务之间的传输与分享；限制上传到未批准的个人网盘、云盘或外部邮箱。 Scope: sensitive-file upload, personal cloud storage, sharing, clipboard and unauthorized outbound information flows.',
  'https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about'),
 'guide-allowlist':(
  '适用范围：终端上哪些应用、二进制、脚本和解释器被允许执行，识别与阻止来源不明、未批准的可执行文件及便携式程序。 Scope: approved software execution, portable applications, unknown executables and unauthorized programs on hosts.',
  'https://csrc.nist.gov/pubs/sp/800/167/final'),
 'guide-csrf':(
  '适用范围：浏览器自动携带会话Cookie的已认证状态变更操作，例如转账、支付、修改账户信息。第三方站点可诱发请求；需要服务端校验不可预测的会话绑定令牌与来源。 Scope: automatically attached session cookies, authenticated state-changing requests, transfers and account changes.',
  'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'),
 'guide-segmentation':(
  '适用范围：访客网络、办公网络、生产网络、数据库网段和管理区域之间的信任边界与访问路径，默认拒绝跨区通信并仅允许业务依赖。 Scope: guest devices, production database subnet, network zones, inter-zone access and lateral movement containment.',
  'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final#SC-7'),
 'guide-dpia':(
  '适用范围：处理活动上线前对个人权利和自由的高风险评估；大规模健康等敏感信息处理、系统性监测、位置轨迹及创新技术可能触发评估。 Scope: planned high-risk processing, large-scale health or other sensitive personal data and systematic monitoring before deployment.',
  'https://europa.eu/youreurope/business/governance-and-sustainability/digital-and-data-compliance/data-protection-gdpr/index_en.htm'),
 'guide-awareness':(
  '适用范围：教育课程、培训参与和完成率之外的实际安全行为、反复人为错误、岗位相关练习、钓鱼演练、事件上报及及时反馈。 Scope: learning effectiveness, behavior change, role-relevant practice, phishing exercises, repeated mistakes and reporting quality.',
  'https://csrc.nist.gov/pubs/sp/800/50/r1/final'),
}
for path in (root/'attack_defense_bot/attack_defense_bot/knowledge').glob('*guides.json'):
    data=json.loads(path.read_text(encoding='utf-8'))
    changed=0
    for doc in data['documents']:
        if doc['id'] in contexts:
            doc['retrieval_context'],doc['retrieval_context_source']=contexts[doc['id']]
            changed+=1
    if changed:
        path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(path.name,changed)
