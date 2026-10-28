import json
from pathlib import Path

folder=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
extra={
    'guide-rest-encryption':('静态数据加密还应覆盖存储快照、数据库文件和备份，降低这些副本泄露时的明文暴露。',
        'Protect stored plaintext in disks, storage snapshots, database files and backups against unauthorized disclosure when those copies leak.'),
    'guide-dns':('集中收集DNS查询与响应日志，关联域名信誉、查询频率、名称新颖度及字符熵，识别隧道并保留主机与调查上下文。',
        'Centralize DNS query and response logs; correlate reputation, frequency, novel names and entropy to detect tunneling while preserving host and investigation context.'),
    'guide-patch':('维护资产与版本清单，结合可利用性、对外暴露和业务关键性排序，经代表性环境测试后分批部署并复测。',
        'Maintain an asset and version inventory, prioritize exploitability, external exposure and business criticality, test representative systems, deploy in stages and verify remediation.'),
}
for name in ['control_guides.json','technical_guides.json']:
    path=folder/name;data=json.loads(path.read_text(encoding='utf-8'))
    for doc in data['documents']:
        if doc['id'] in extra:
            zh,en=extra[doc['id']]
            if zh not in doc['text_zh']:doc['text_zh']+=' '+zh
            if en not in doc['text_en']:doc['text_en']=en+' '+doc['text_en']
            doc['text']=doc['text_zh']+'\n'+doc['text_en']
        if doc['id']=='guide-secrets':
            doc['title']='Centralized secrets management / 应用凭据与机密集中管理'
            doc['aliases']+=' 数据库密码 凭据硬编码 集中式密钥管理 应用机密 源代码仓库'
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
print('Refined source-supported deployment details.')
