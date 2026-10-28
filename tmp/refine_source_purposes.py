"""Curate standards-based purpose statements; no evaluation records exported."""
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
revisions={
    'guide-patch':{
        'text_en':'Patch and remediation management reduces exposure to known software vulnerabilities by applying and verifying security fixes promptly, with priority for exploitable and externally exposed flaws. ',
        'source':'https://csrc.nist.gov/pubs/sp/800/40/r4/final',
    },
    'guide-firmware':{
        'text_zh':'固件安全更新及时修复设备底层漏洞；验证更新签名、授权版本和完整性，阻止伪造固件及回滚到易受攻击版本。安装失败时应保持安全状态并使用经过保护的恢复机制。 ',
    },
    'guide-container':{
        'text_zh':'部署前扫描容器镜像中的已知漏洞并验证签名与可信来源，通过准入策略阻止含高风险漏洞、被篡改或来源不明的镜像进入运行环境。扫描和签名分别处理组件漏洞与来源完整性，不能相互替代。 ',
    },
}
for path in [root/'control_guides.json',root/'technical_guides.json']:
    obj=json.loads(path.read_text(encoding='utf-8'))
    for doc in obj['documents']:
        changes=revisions.get(doc['id'],{})
        for key,value in changes.items():
            if key=='source':doc[key]=value
            elif not doc[key].startswith(value):doc[key]=value+doc[key]
        if changes:doc['text']=doc['text_zh']+'\n'+doc['text_en']
    path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
print('Updated',len(revisions),'source summaries')
