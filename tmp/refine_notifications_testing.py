import json
from pathlib import Path
folder=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
updates={
'guide-notification':('', 'Incident notification supports timely internal escalation, regulatory reporting and affected-party notice when applicable, with documented responsibilities and deadlines.'),
'guide-sast-dast':('不能只依赖发布后人工发现问题，应把静态代码分析、依赖检查和动态安全测试集成到开发流水线，在发布前尽早发现缺陷，并对高风险问题设置修复门槛。',
    'Shift security testing before release by combining static analysis, dependency checks and dynamic tests in the pipeline, with remediation gates for high-risk findings.'),
}
for name in ['control_guides.json','technical_guides.json']:
    path=folder/name;data=json.loads(path.read_text(encoding='utf-8'))
    for doc in data['documents']:
        if doc['id'] in updates:
            zh,en=updates[doc['id']]
            if zh and zh not in doc['text_zh']:doc['text_zh']+=' '+zh
            if en and en not in doc['text_en']:doc['text_en']=en+' '+doc['text_en']
        if doc['id']=='guide-sast-dast' and '发布后人工' not in doc['aliases']:
            doc['aliases']+=' 发布后人工 手工检查 自动测试 缺陷发现前移 流水线 修复门禁 shift-left testing'
        doc['text']=doc['text_zh']+'\n'+doc['text_en']
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
print('Completed notification recipients and early application-testing context.')
