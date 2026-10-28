"""Complete implementation details from NIST AC-2 and CISA memory safety."""
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
updates={
 'guide-identity':{
  'text_zh':'以权威人事系统的入职、转岗和离职状态事件触发账户开通、调整及停用撤销，规定处置时限；对状态异常、孤儿账户和逾期撤权告警，保留审批与执行记录。 ',
  'text_en':'Connect authoritative personnel events for joiners, movers and leavers to account provisioning, changes and deprovisioning, with defined response deadlines and alerts for orphaned, inconsistent or overdue accounts. Retain approvals and execution records. ',
 },
 'guide-memory':{
  'text_zh':'新编写的复杂二进制解析器可通过内存安全语言和可靠的边界检查，在实现层防止越界读写和释放后使用等缺陷。沙箱限制缺陷被利用后的影响范围，不能替代这一缺陷预防。 ',
  'text_en':'For newly written parsers of complex binary data, memory-safe implementation prevents classes of out-of-bounds access and use-after-free defects. Sandboxing limits the impact of exploitation; it does not remove these implementation defects. ',
  'source':'https://www.cisa.gov/sites/default/files/2023-12/The-Case-for-Memory-Safe-Roadmaps-508c.pdf',
 },
}
for path in [root/'control_guides.json',root/'technical_guides.json']:
 obj=json.loads(path.read_text(encoding='utf-8'))
 for doc in obj['documents']:
  for key,value in updates.get(doc['id'],{}).items():
   if key=='source':doc[key]=value
   elif not doc[key].startswith(value):doc[key]=value+doc[key]
  if doc['id'] in updates:doc['text']=doc['text_zh']+'\n'+doc['text_en']
  if doc['id']=='guide-cloud-kms':
   for name in ['云加密密钥','cloud encryption key','cloud encryption keys']:
    if name not in doc['topic_names']:doc['topic_names'].append(name)
 path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
print('Updated implementation boundaries and cloud encryption-key terms')
