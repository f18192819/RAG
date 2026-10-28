"""Enforce the user's two-upload cap for the current optimization request."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from platform_client import session, BASE, SLUG

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--version',required=True)
args=parser.parse_args()
ledger=root/'output/limited_two_submissions_20261028.json'
state=json.loads(ledger.read_text(encoding='utf-8'))
if len(state['attempts'])>=state['max_uploads']:
    raise SystemExit('The two-upload limit has been reached; do not submit again.')
client=session()
latest=client.get(f'{BASE}/api/assignments/{SLUG}/submissions/latest',timeout=20)
latest.raise_for_status()
if latest.json() and latest.json()['status'] in {'queued','preparing','installing','evaluating'}:
    raise SystemExit('Official grading is still active; no upload attempted.')
attempt={'version':args.version,'started_at':datetime.now(timezone.utc).isoformat(),'status':'submitting'}
state['attempts'].append(attempt)
ledger.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
result=subprocess.run([sys.executable,str(root/'tmp/platform_client.py'),'submit','--version',args.version])
record=root/'output'/('submission_'+args.version+'.json')
if record.exists():
    attempt.update(json.loads(record.read_text(encoding='utf-8')))
else:
    attempt['status']='submission_not_confirmed'
ledger.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
raise SystemExit(result.returncode)
