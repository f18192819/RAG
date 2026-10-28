"""Verify a real public record beyond the bundled lexical snapshot."""
import json
from pathlib import Path
import re
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'attack_defense_bot/attack_defense_bot'))
from config import load_settings
from api_client import RagApiClient
from main import answer_question
from evidence import matching_course_qa
from reference_search import remember_public_sources

settings=load_settings()
client=RagApiClient(settings)
rows=client.search('common_dataset','DNS',top_k=3,expr='file_id > 459970008184540901')
remember_public_sources(rows)
for source in rows:
    match=re.match(r'Question:\s*(.*?)\s*Answer:',source['text'],re.S)
    if not match:continue
    question=match.group(1)
    reference=matching_course_qa(question,source)
    if not reference:continue
    response,citations=answer_question(question,settings)
    answer=json.loads(response)
    result={'source_id':str(source['file_id']),'decision':answer['decision'],
            'complete_source_preserved':reference['quote'] in answer.get('answer',''),
            'citations':citations}
    print(json.dumps(result,ensure_ascii=False))
    (root/'output/v21_new_public_faq_check.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    if not result['complete_source_preserved']:raise SystemExit(1)
    break
else:raise SystemExit('No source suitable for the exact-FAQ check')
