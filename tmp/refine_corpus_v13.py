import json
from pathlib import Path
folder=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
for name in ['control_guides.json','technical_guides.json']:
    path=folder/name;data=json.loads(path.read_text(encoding='utf-8'))
    for doc in data['documents']:
        if doc['id']=='guide-host-backup':
            extra='具体威胁包括勒索软件、误删除和设备损坏；目标是恢复关键数据、系统配置和必要的主机状态，避免中断演变成严重业务事件。'
            if extra not in doc['text_zh']:doc['text_zh']+=' '+extra
            extra_en='Recover critical data, configurations and host state after ransomware, accidental deletion or hardware damage, limiting business disruption.'
            if extra_en not in doc['text_en']:doc['text_en']=extra_en+' '+doc['text_en']
        if doc['id']=='guide-random':
            extra='核心用途是让密钥、令牌和认证挑战不可预测；随机性不等于严格唯一性，后者仍需独立设计和验证。'
            if extra not in doc['text_zh']:doc['text_zh']+=' '+extra
            extra_en='Cryptographically secure randomness provides unpredictability for keys, tokens and authentication challenges; randomness alone does not guarantee uniqueness.'
            if extra_en not in doc['text_en']:doc['text_en']=extra_en+' '+doc['text_en']
        if doc['id']=='guide-zero':
            doc['title']='Risk-based conditional access and zero trust / 基于风险的条件访问与零信任'
            if '基于风险的条件访问' not in doc['aliases']:doc['aliases']+=' 基于风险的条件访问 风险信号 设备合规 地理位置 资源敏感度'
        doc['text']=doc['text_zh']+'\n'+doc['text_en']
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
print('Refined protected objects, failure modes and exact control terminology.')
