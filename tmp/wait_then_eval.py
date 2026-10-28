"""Keep local online tests sequential with official grading."""
import argparse
import json
from pathlib import Path
import sys
import time

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--dataset',required=True)
parser.add_argument('--output-dir',required=True)
parser.add_argument('--package-dir',default=str(root/'attack_defense_bot/attack_defense_bot'))
args=parser.parse_args()
sys.path[:0]=[str(root/'tmp'),str(Path(args.package_dir).resolve())]
from platform_client import session,BASE,SLUG
import eval_dataset
client=session()
for attempt in range(80):
    response=client.get(f'{BASE}/api/assignments/{SLUG}/submissions/latest',timeout=20)
    response.raise_for_status()
    status=response.json()
    if not status or status.get('status') not in {'queued','preparing','installing','evaluating'}:
        print('Official grading completed; starting local validation.',flush=True)
        break
    if attempt%2==0:print('Waiting for official grading:',status.get('status'),flush=True)
    time.sleep(30)
else:raise SystemExit('Official grading remains active; local validation did not start.')
sys.argv=['eval_dataset.py','--dataset',args.dataset,'--output-dir',args.output_dir,
          '--concurrency','5','--progress-every','20']
raise SystemExit(eval_dataset.main())
