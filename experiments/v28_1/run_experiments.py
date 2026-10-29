"""Same-condition A/H/H1/H2/H3 inference; no scoring labels enter the pipeline."""
from concurrent.futures import ThreadPoolExecutor,as_completed
from dataclasses import replace,asdict
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
sys.path[:0]=[str(PACKAGE),str(ROOT/'experiments/v28'),str(HERE)]
from config import load_settings
from api_client import RagApiClient
from diagnostics import capture_diagnostics,record
import diagnostics
from run_ablations import CachedClient,preflight,install_legacy_diagnostics

VARIANTS={
 'A':{'production_profile':'A','candidate_retention':False,'answer_completeness':False},
 'H':{'production_profile':'candidate','candidate_retention':False,'answer_completeness':False},
 'H1':{'production_profile':'candidate','candidate_retention':True,'answer_completeness':False},
 'H2':{'production_profile':'candidate','candidate_retention':False,'answer_completeness':True},
 'H3':{'production_profile':'candidate','candidate_retention':True,'answer_completeness':True},
}


def fingerprint(paths):
    digest=hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode()+b'\0')
        digest.update(path.read_text(encoding='utf-8').encode()+b'\0')
    return digest.hexdigest()


def source_state():
    return {
      'inference_sha256':fingerprint(list(PACKAGE.glob('*.py'))+list((PACKAGE/'baseline_v17').glob('*.py'))),
      'knowledge_sha256':fingerprint([p for p in (PACKAGE/'knowledge').iterdir() if p.suffix in {'.json','.jsonl'}]),
      'h_snapshot_sha256':fingerprint(list((HERE/'snapshot_h').glob('*.py'))),
      'split_manifest_sha256':hashlib.sha256((ROOT/'experiments/v28/splits.json').read_bytes()).hexdigest(),
    }


def settings_for(key):
    return replace(load_settings(),database_name='common_dataset',personal_database_name='',temperature=0,
        max_tokens=1000,top_k=5,context_max_files=5,context_max_chars=6000,score_threshold=0.0,
        choice_strategy='rag',query_representation=False,contrastive_rerank=False,**VARIANTS[key])


def run(key,split):
    frozen=HERE/'results/source_freeze.json'
    if not frozen.exists() or json.loads(frozen.read_text())!=source_state():
        raise SystemExit('Inference/source state differs from the frozen experiment.')
    if split=='holdout' and not (HERE/'results/selection.json').exists():
        raise SystemExit('Freeze validation selection before any holdout inference.')
    result_dir=HERE/'results';result_dir.mkdir(exist_ok=True)
    target=result_dir/f'{key}_{split}_details.jsonl'
    if target.exists():raise SystemExit('Existing experiment refused; no adaptive regeneration.')
    ready,reason=preflight()
    if not ready:raise SystemExit('Model API unavailable: '+reason)
    settings=settings_for(key)
    cached=CachedClient(RagApiClient(settings),settings.api_token,HERE/'cache')
    if key=='H':
        folder=HERE/'snapshot_h/knowledge';folder.mkdir(exist_ok=True)
        for path in (PACKAGE/'knowledge').iterdir():
            if path.suffix in {'.json','.jsonl'}:shutil.copyfile(path,folder/path.name)
        sys.modules['snapshot_h.diagnostics']=diagnostics
        main=importlib.import_module('snapshot_h.main')
    elif key=='A':
        main=importlib.import_module('baseline_v17.main')
        install_legacy_diagnostics(main,None,'A',None)
    else:main=importlib.import_module('main')
    main.RagApiClient=lambda unused:cached
    manifest=json.loads((ROOT/'experiments/v28/splits.json').read_text(encoding='utf-8'))
    ids=set(manifest['evaluation_subset'][split])
    rows=[json.loads(line) for line in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
    selected=[row for row in rows if row['id'] in ids]
    def one(row):
        trace={};started=time.monotonic();response={'decision':'error','answer':''};error=None
        with capture_diagnostics(trace,settings.api_token):
            try:
                raw,_=main.answer_question(row['input']['text'],settings);response=json.loads(raw)
            except Exception as exc:error=type(exc).__name__
            record('generation',answer=response.get('answer'),decision=response['decision'])
        return {'question_id':row['id'],'question_type':'multiple_choice' if row['expected']['answer'] in {'A','B','C','D'} else 'short_answer',
                **trace,'latency_seconds':round(time.monotonic()-started,3),'error_type':error}
    outputs=[]
    with target.open('w',encoding='utf-8') as stream,ThreadPoolExecutor(max_workers=4) as pool:
        for future in as_completed([pool.submit(one,row) for row in selected]):
            item=future.result();outputs.append(item);stream.write(json.dumps(item,ensure_ascii=False)+'\n');stream.flush()
            if len(outputs)%5==0:print(key,split,len(outputs),'/',len(selected),flush=True)
    public_config={key:value for key,value in asdict(settings).items() if key not in {'api_token','api_base_url'}}
    summary={'variant':key,'split':split,'samples':len(outputs),'real_model_inference':True,
             'strict_scoring_complete':False,'run_configuration':VARIANTS[key],
             'model_configuration':public_config,'source_state':source_state(),
             'error_count':sum(bool(r['error_type']) for r in outputs)}
    (result_dir/f'{key}_{split}_summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(key,split,'inference completed; errors',summary['error_count'],flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--variant',choices=list(VARIANTS));parser.add_argument('--split',choices=['validation','holdout'],default='validation')
    args=parser.parse_args()
    if args.variant:return run(args.variant,args.split)
    frozen=HERE/'results/source_freeze.json'
    state=source_state()
    if frozen.exists() and json.loads(frozen.read_text())!=state:raise SystemExit('Code/sources changed after experiment freeze.')
    frozen.parent.mkdir(exist_ok=True);frozen.write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8')
    for key in VARIANTS:
        subprocess.run([sys.executable,__file__,'--variant',key,'--split',args.split],check=True)


if __name__=='__main__':main()
