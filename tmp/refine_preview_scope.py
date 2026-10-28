import json
from pathlib import Path
path=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge/technical_guides.json'
obj=json.loads(path.read_text(encoding='utf-8'))
for doc in obj['documents']:
 if doc['id']!='guide-sandbox':continue
 zh='既有文档预览服务或外部组件处理不可信文件时，可用独立低权限沙箱限制文件、网络、系统调用和资源，降低解析漏洞或恶意输入对宿主的影响。运行时隔离可保留既有实现；内存安全重写则针对实现缺陷类别，二者的实施约束不同。 '
 en='Existing document-preview services and third-party parsers can use separate low-privilege sandboxes to restrict files, network access, system calls and resources. Runtime isolation limits impact while retaining the existing implementation; memory-safe rewriting addresses defect classes under different implementation constraints. '
 if not doc['text_zh'].startswith(zh):doc['text_zh']=zh+doc['text_zh']
 if not doc['text_en'].startswith(en):doc['text_en']=en+doc['text_en']
 doc['text']=doc['text_zh']+'\n'+doc['text_en']
 extra=' 文档预览 不可信文件 文件解析 第三方组件 受限进程隔离 document preview untrusted files existing parser'
 if extra not in doc['aliases']:doc['aliases']+=extra
 doc['additional_sources']=['https://www.cisa.gov/sites/default/files/2023-12/The-Case-for-Memory-Safe-Roadmaps-508c.pdf']
path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
print('Clarified existing-parser isolation scope')
