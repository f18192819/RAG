"""Source-supported completeness fixes from development error analysis."""
import json
from pathlib import Path
folder=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
updates={
'guide-identity':('', 'Identity lifecycle management makes joiner, mover and leaver (JML) access changes timely and auditable.'),
'guide-data-classification':('先制定分类标准并指定数据责任人，盘点数据及存储位置，维护分类标记，并把访问、保留和处置规则映射到各等级。',
    'Data classification applies protection according to information sensitivity and business impact, with accountable owners and a maintained inventory.'),
'guide-memory':('', 'Memory safety reduces memory-corruption defects, including out-of-bounds access and use-after-free flaws, rather than merely making exploitation harder.'),
'guide-firmware':('', 'Verified firmware updates patch low-level flaws while rejecting forged updates and unauthorized rollback to vulnerable firmware versions.'),
'guide-vulnerability':('', 'Closed-loop vulnerability management connects discovery, prioritization, remediation, validation and governed exceptions in a traceable workflow.'),
'guide-zero':('实施时定义可解释的风险信号，按风险分级配置认证加强或阻断动作，并持续监测误报和业务影响。', ''),
'guide-secure-boot':('在操作系统加载前验证固件和引导程序，只允许受信任的引导组件进入执行链；配合版本与回滚策略，保护恢复密钥和信任根。',
    'Before the operating system loads, verify firmware and bootloader components against protected trust anchors; combine signature checks with version/rollback policy and protected recovery secrets.'),
'guide-third-party':('关键供应商远程接入前需分层尽职调查和安全评估，合作全生命周期持续监督，并在退出时撤销访问、返还或删除数据。',''),
}
for name in ['control_guides.json','technical_guides.json']:
    path=folder/name;data=json.loads(path.read_text(encoding='utf-8'))
    for doc in data['documents']:
        if doc['id'] in updates:
            zh,en=updates[doc['id']]
            if zh and zh not in doc['text_zh']:doc['text_zh']+=' '+zh
            if en and en not in doc['text_en']:doc['text_en']=en+' '+doc['text_en']
        if doc['id']=='guide-third-party':
            doc['title']='Third-party and supplier risk management / 第三方与供应商风险管理'
            if '供应商安全评估' not in doc['aliases']:doc['aliases']+=' 供应商安全评估 远程接入 准入尽职调查 合作生命周期 定期复评'
        if doc['id']=='guide-secure-boot' and '引导程序' not in doc['aliases']:
            doc['aliases']+=' 引导程序 引导链 bootloader 操作系统加载前 启动固件'
        doc['text']=doc['text_zh']+'\n'+doc['text_en']
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
print('Completed source-supported lifecycle terms, protected objects and operational conditions.')
