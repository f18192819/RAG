"""One authorized classroom submission, with credentials kept outside the ZIP."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile
import requests
ROOT=Path(__file__).resolve().parents[1]
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
sys.path.insert(0,str(PACKAGE))
from credentials import load_credentials

BASE='http://10.1.0.220:9010'
SLUG='assignment3'
INFERENCE={'__init__.py','api_client.py','config.py','credentials.py','data_processor.py',
 'diagnostics.py','evidence.py','guard.py','intents.py','main.py','prompt_builder.py',
 'question_format.py','query_planning.py','control_routing.py','reference_search.py','retrieval.py','utils.py'}


def inference_fingerprint():
    files=[PACKAGE/name for name in sorted(INFERENCE)]+[PACKAGE/'requirements.txt']
    files+=sorted((PACKAGE/'knowledge').glob('*.json'))+sorted((PACKAGE/'knowledge').glob('*.jsonl'))
    digest=hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(PACKAGE).as_posix().encode()+b'\0')
        digest.update(path.read_text(encoding='utf-8').encode('utf-8')+b'\0')
    return digest.hexdigest()


def require_completed_ablation():
    folder=ROOT/'experiments/v28/results'
    manifest_sha=hashlib.sha256((ROOT/'experiments/v28/splits.json').read_bytes()).hexdigest()
    selection_path=folder/'selection.json'
    if not selection_path.exists():raise SystemExit('Validation must select a frozen clean profile before upload.')
    selection=json.loads(selection_path.read_text(encoding='utf-8'))
    chosen=selection['selected_variant']
    profile=json.loads((PACKAGE/'pipeline_profile.json').read_text(encoding='utf-8'))
    for variant,split in [(key,'validation') for key in 'ABCDEFGHI']+[('A','holdout'),(chosen,'holdout')]:
        path=folder/(variant+'_'+split+'_summary.json')
        if not path.exists():raise SystemExit('Real ablation/holdout results are required before the one platform upload.')
        result=json.loads(path.read_text(encoding='utf-8'))
        if not result.get('real_model_inference') or not result.get('strict_scoring_complete') or result.get('split_manifest_sha256')!=manifest_sha:
            raise SystemExit('Missing or stale real ablation evidence; no platform upload attempted.')
        if variant in 'FGHI' and result.get('inference_source_sha256')!=inference_fingerprint():
            raise SystemExit('Inference code changed after validation; no platform upload attempted.')
        if variant==chosen and result.get('run_configuration')!={key:profile[key] for key in ['query_representation','contrastive_rerank']}:
            raise SystemExit('Selected profile differs from evaluated configuration; no upload attempted.')


def session():
    credentials=load_credentials()
    client=requests.Session();client.trust_env=False
    response=client.post(BASE+'/api/auth/student-login',json={'student_id':credentials['student_id'],'token':credentials['token']},timeout=20)
    response.raise_for_status();client.headers['X-CSRF-Token']=response.json()['csrf_token']
    return client


def build_submission(version):
    target=ROOT/'output'/('course_'+version+'.zip');target.parent.mkdir(exist_ok=True)
    files=[PACKAGE/name for name in sorted(INFERENCE)]+[PACKAGE/'requirements.txt',PACKAGE/'README.md',PACKAGE/'pipeline_profile.json']
    files+=sorted((PACKAGE/'knowledge').glob('*.json'))+sorted((PACKAGE/'knowledge').glob('*.jsonl'))
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
        for path in files:
            if not path.is_file():raise ValueError('Missing inference source: '+path.name)
            z.write(path,'attack_defense_bot/'+path.relative_to(PACKAGE).as_posix())
    manifest={'archive':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
              'files':[str(path.relative_to(PACKAGE)) for path in files],'credentials_included':False}
    return target,manifest


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['status','submit','board','build'])
    parser.add_argument('--version',default='v28_clean');args=parser.parse_args()
    if args.action=='build':
        target,manifest=build_submission(args.version);print(json.dumps(manifest,ensure_ascii=False));return
    if args.action=='submit':require_completed_ablation()
    client=session()
    latest_url=f'{BASE}/api/assignments/{SLUG}/submissions/latest'
    if args.action=='submit':
        record=ROOT/'experiments/v28/results/platform_submission.json'
        if record.exists():raise SystemExit('This task permits one platform upload; a submission attempt is already recorded.')
        latest=client.get(latest_url,timeout=20);latest.raise_for_status()
        if latest.json() and latest.json()['status'] in {'queued','preparing','installing','evaluating'}:
            raise SystemExit('Another evaluation is active; no upload attempted.')
        archive,manifest=build_submission(args.version)
        record.parent.mkdir(parents=True,exist_ok=True)
        attempt={'version':args.version,'status':'submitting','manifest':manifest}
        record.write_text(json.dumps(attempt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        with archive.open('rb') as stream:
            response=client.post(f'{BASE}/api/assignments/{SLUG}/submissions',files={'file':(archive.name,stream,'application/zip')},timeout=60)
        response.raise_for_status();attempt.update(response.json())
        record.write_text(json.dumps(attempt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(response.json(),ensure_ascii=False))
    elif args.action=='status':
        response=client.get(latest_url,timeout=20);response.raise_for_status();item=response.json()
        print(json.dumps(item,ensure_ascii=False))
        record=ROOT/'experiments/v28/results/platform_submission.json'
        if record.exists():
            attempt=json.loads(record.read_text(encoding='utf-8'))
            if item and item.get('id')==attempt.get('submission_id'):
                attempt['result']=item;record.write_text(json.dumps(attempt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    else:
        response=client.get(f'{BASE}/api/assignments/{SLUG}/leaderboard',timeout=20);response.raise_for_status()
        board=response.json();board['entries']=[entry for entry in board.get('entries',[]) if entry.get('is_me')]
        print(json.dumps(board,ensure_ascii=False))

if __name__=='__main__':main()
