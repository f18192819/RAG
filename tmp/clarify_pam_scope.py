import json
import sys
from pathlib import Path
path=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge/control_guides.json'
obj=json.loads(path.read_text(encoding='utf-8'))
for doc in obj['documents']:
    if doc['id']!='guide-pam':continue
    zh='角色定义、职责分离和定期权限复核是授权治理，不能替代PAM对特权凭据、即时提权与管理会话的直接控制。 '
    en='Role design, separation of duties and access recertification govern authorization; they do not replace PAM controls over privileged credentials, just-in-time elevation and administrative sessions. '
    if '--revert' in sys.argv:
        doc['text_zh']=doc['text_zh'].replace(zh,'')
        doc['text_en']=doc['text_en'].replace(en,'')
    else:
        if zh not in doc['text_zh']:doc['text_zh']+=zh
        if en not in doc['text_en']:doc['text_en']+=en
    doc['text']=doc['text_zh']+'\n'+doc['text_en']
path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
print('Clarified PAM control scope')
