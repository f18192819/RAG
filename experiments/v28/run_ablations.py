"""Reproducible online ablations; refuses to invent scores if the API is offline.

A-D execute preserved v17 inference. E changes its routing module, bounded
authority and competing-source survival together. F evaluates the clean runtime.
All variants share source documents, settings, frozen IDs and an API cache.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import importlib.util
import importlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[2]
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
HERE=Path(__file__).resolve().parent


def prepare_baseline():
    source=PACKAGE/'knowledge';target=HERE/'baseline_v17/knowledge';target.mkdir(parents=True,exist_ok=True)
    for path in source.iterdir():
        if path.name!='control_scope.json' and path.suffix in {'.json','.jsonl'}:shutil.copyfile(path,target/path.name)


def preflight():
    endpoint=os.getenv('RAG_API_BASE_URL','http://10.1.0.220:9002/api')
    parsed=urlsplit(endpoint)
    try:
        with socket.create_connection((parsed.hostname,parsed.port or (443 if parsed.scheme=='https' else 80)),timeout=3):pass
        return True,None
    except OSError as exc:return False,type(exc).__name__


class CachedClient:
    """Caches public source responses and normal model outputs, never prompts."""
    def __init__(self,client,secret,cache_dir):
        self.client=client;self.secret=secret;self.folder=cache_dir;self.folder.mkdir(parents=True,exist_ok=True)
        self.lock=threading.Lock()

    def _call(self,method,args,kwargs):
        key=hashlib.sha256(json.dumps([method,args,kwargs],ensure_ascii=False,sort_keys=True).encode()).hexdigest()
        path=self.folder/(key+'.json')
        with self.lock:
            if path.exists():return json.loads(path.read_text(encoding='utf-8'))['response']
        response=getattr(self.client,method)(*args,**kwargs)
        text=json.dumps({'response':response},ensure_ascii=False)
        if self.secret and self.secret in text:raise ValueError('Credential-like response refused; not cached')
        with self.lock:path.write_text(text,encoding='utf-8')
        return response

    def search(self,*args,**kwargs):return self._call('search',args,kwargs)
    def dialogue(self,*args,**kwargs):return self._call('dialogue',args,kwargs)


def install_legacy_diagnostics(main,trace_module,variant,modern_evidence):
    from control_routing import route_candidate_guides,contrastive_rerank_guides
    from query_planning import plan_query_representation
    from diagnostics import record,source_ids
    from contextvars import ContextVar
    active_routed=ContextVar('legacy_routed',default=())
    active_catalog=ContextVar('legacy_catalog',default=())
    active_features=ContextVar('legacy_features',default={})
    evidence_mode=ContextVar('legacy_evidence_mode',default='llm')
    original_plan=main.plan_queries;original_router=main.route_guides
    original_fuse=main.fuse_rankings;original_prepare=main.prepare_context;original_isolate=main.isolate_evidence

    def plan(question,client):
        active_routed.set(())
        active_catalog.set(())
        if variant in {'A','C'}:queries=original_plan(question,client);active_features.set({})
        else:
            representation=plan_query_representation(question,client)
            queries=representation.queries;active_features.set(representation.features)
        record('retrieval',queries=queries)
        return queries

    def router(question,client,candidates=None):
        if variant in {'C','D'}:
            # Preserve the existing lexical candidate-generation stage while
            # removing only its unique semantic decision and source pruning.
            generated=main.local_search(main.question_stem(question),20)
            catalog=[]
            for hit in generated+list(candidates or []):
                key=source_ids([hit])[0]
                if key.startswith('guide-') and key not in catalog:catalog.append(key)
            record('retrieval',candidate_sources=catalog[:18])
            active_catalog.set(tuple(catalog[:18]))
            selected=[]
        elif variant=='E':
            candidates=route_candidate_guides(question,candidates or [])
            selected=contrastive_rerank_guides(question,active_features.get(),candidates,client)[0]
        else:
            strong=main.strong_lexical_guide(question)
            catalog=source_ids(strong) if strong else []
            if not strong:
                for hit in main.local_search(main.question_stem(question),20)+list(candidates or []):
                    key=source_ids([hit])[0]
                    if key.startswith('guide-') and key not in catalog:catalog.append(key)
                catalog=catalog[:18]
            active_catalog.set(tuple(catalog));record('retrieval',candidate_sources=catalog)
            selected=original_router(question,client,candidates)
        active_routed.set(tuple(source_ids(selected)))
        if variant!='E':record('router',candidate_controls=source_ids(selected),ranking=[],top1_margin=None)
        return selected

    def fuse(routes,max_files=5):
        independent=[pair for pair in routes if pair[0]!=3.5]
        record('retrieval',document_sources=source_ids(original_fuse(independent,20)))
        if not active_routed.get() and not active_catalog.get():
            guide_routes=[(weight,[hit for hit in hits if source_ids([hit])[0].startswith('guide-')]) for weight,hits in independent]
            record('retrieval',candidate_sources=source_ids(original_fuse(guide_routes,20)))
        adjusted=[(1.0 if weight==3.5 and variant=='E' else weight,items) for weight,items in routes]
        result=original_fuse(adjusted,max_files)
        record('fusion',sources=source_ids(result))
        return result

    def prepare(files,*args,**kwargs):
        context,kept=original_prepare(files,*args,**kwargs)
        record('prepared',sources=source_ids(kept))
        return context,kept

    original_fallback=original_isolate.__globals__['fallback_evidence']
    def fallback(*args,**kwargs):
        evidence_mode.set('fallback');return original_fallback(*args,**kwargs)
    original_isolate.__globals__['fallback_evidence']=fallback

    def isolate(question,files,client,primary_source_id=''):
        if variant=='E' and active_routed.get():
            return modern_evidence.isolate_evidence(question,files,client,retained_source_ids=active_routed.get())
        evidence_mode.set('llm')
        called={'extractor':False}
        class Tap:
            def dialogue(self,*args,**kwargs):called['extractor']=True;return client.dialogue(*args,**kwargs)
        # Observe the actual legacy fallback call, not an inferred success label.
        context,kept=original_isolate(question,files,Tap(),primary_source_id)
        mode=evidence_mode.get()
        if primary_source_id and not called['extractor'] and len(kept)==1:mode='deterministic_guide'
        record('evidence',mode=mode,retained_sources=source_ids(kept),fallback_used=mode=='fallback')
        return context,kept
    main.plan_queries=plan;main.route_guides=router;main.fuse_rankings=fuse;main.prepare_context=prepare;main.isolate_evidence=isolate


def run_variant(args):
    prepare_baseline()
    clean=args.variant in 'FGHI'
    sys.path.insert(0,str(PACKAGE if clean else HERE/'baseline_v17'))
    import main,config
    # Load external credentials without displaying them or copying a private .env.
    spec=importlib.util.spec_from_file_location('external_auth',PACKAGE/'credentials.py')
    auth=importlib.util.module_from_spec(spec);spec.loader.exec_module(auth)
    credential={'token':'contract-test-only'} if args.smoke else auth.load_credentials()
    os.environ['RAG_API_TOKEN']=credential['token'];os.environ['RAG_PERSONAL_DATABASE']=''
    os.environ['RAG_TEMPERATURE']='0';os.environ['RAG_MAX_TOKENS']='1000'
    os.environ['RAG_TOP_K']='5';os.environ['RAG_CONTEXT_MAX_FILES']='5';os.environ['RAG_CONTEXT_MAX_CHARS']='6000'
    flags={'query_representation':args.variant not in 'HI','contrastive_rerank':args.variant in 'FI'}
    if clean:
        os.environ['RAG_QUERY_REPRESENTATION']=str(flags['query_representation'])
        os.environ['RAG_CONTRASTIVE_RERANK']=str(flags['contrastive_rerank'])
    settings=config.load_settings()
    # Modern development utilities can import the already-loaded legacy source
    # registry, while the baseline main/prompt/guard themselves remain preserved.
    sys.path.insert(0,str(PACKAGE));sys.path.insert(0,str(HERE))
    from diagnostics import capture_diagnostics,record
    from semantic_evaluator import evaluate,aggregate
    import types,diagnostics
    adapter=types.ModuleType('v28_adapter');adapter.__path__=[str(PACKAGE)]
    sys.modules['v28_adapter']=adapter;sys.modules['v28_adapter.diagnostics']=diagnostics
    modern=importlib.import_module('v28_adapter.evidence')
    if not clean:install_legacy_diagnostics(main,None,args.variant,modern)
    original_factory=main.RagApiClient
    if args.smoke:
        from retrieval import index,guide_file
        class ContractClient:
            def search(self,*unused,**kwargs):return [guide_file(doc) for doc in index()[0] if doc['id']=='guide-fde']
            def dialogue(self,**kwargs):
                prompt=kwargs['custom_prompt']
                if prompt.startswith('Represent a cybersecurity'):return json.dumps({'queries':[],'features':{'protected_object':'','failure_mode':'','lifecycle_stage':'','environment':'','identifiers':[]}})
                if prompt.startswith('You rewrite a cybersecurity'):return '{"queries":[]}'
                if prompt.startswith('You are a retrieval router'):return '{"source_ids":["guide-fde"]}'
                if prompt.startswith('Compare the supplied'):
                    catalog=json.loads(prompt.split('DATA_JSON=',1)[1])['candidates']
                    return json.dumps({'ranking':[{'source_id':row['source_id'],'score':0.9 if row['source_id']=='guide-fde' else 0.3,'reason_code':'object_match'} for row in catalog]})
                if prompt.startswith('You are EVIDENCE_EXTRACTOR'):return '{"evidence":[]}'
                return '{"decision":"answer","answer":"Full disk encryption protects offline storage.","evidence":[]}'
        cached=ContractClient()
    else:cached=CachedClient(original_factory(settings),settings.api_token,HERE/'cache')
    main.RagApiClient=lambda unused:cached
    if args.smoke:
        trace={}
        with capture_diagnostics(trace):
            result,_=main.answer_question('A portable workstation was stolen. Which measure protects its stored information?',settings)
        assert json.loads(result)['decision']=='answer'
        assert 'retrieval' in trace and 'evidence' in trace
        print(args.variant,'contract smoke passed; no model-quality metrics generated.')
        return
    manifest=json.loads((HERE/'splits.json').read_text(encoding='utf-8'))
    ids=set(manifest['evaluation_subset'][args.split])
    rows=[json.loads(line) for line in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines()]
    selected=[row for row in rows if row['id'] in ids]
    result_dir=HERE/'results';result_dir.mkdir(exist_ok=True)
    details=result_dir/(args.variant+'_'+args.split+'_details.jsonl')
    if details.exists():raise SystemExit('Frozen experiment already exists; refusing an adaptive rerun.')
    outputs=[]
    def run(row):
        trace={};started=time.monotonic();response={'decision':'error','answer':''};error=None
        with capture_diagnostics(trace,settings.api_token):
            try:
                raw,_=main.answer_question(row['input']['text'],settings)
                response=json.loads(raw)
            except Exception as exc:error=type(exc).__name__
            record('generation',answer=response.get('answer'),decision=response['decision'])
        result={'question_id':row['id'],'question_type':'multiple_choice' if row['expected']['answer'] in {'A','B','C','D'} else 'short_answer',
                **trace,'latency_seconds':round(time.monotonic()-started,3),'error_type':error}
        result['evaluation']=evaluate(row,response,trace,manifest['canonical_controls'])
        return result
    workers=args.concurrency
    with details.open('w',encoding='utf-8') as stream,ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(run,row) for row in selected]):
            value=future.result();outputs.append(value);stream.write(json.dumps(value,ensure_ascii=False)+'\n');stream.flush()
            if len(outputs)%5==0:print(args.variant,args.split,len(outputs),'/',len(selected),flush=True)
    summary=aggregate(outputs);summary.update(variant=args.variant,split=args.split,real_model_inference=True,
                                              split_manifest_sha256=hashlib.sha256((HERE/'splits.json').read_bytes()).hexdigest())
    if clean:
        sys.path.insert(0,str(ROOT/'tools'))
        from platform_client import inference_fingerprint
        summary['inference_source_sha256']=inference_fingerprint()
        summary['run_configuration']=flags
    (result_dir/(args.variant+'_'+args.split+'_summary.json')).write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False),flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--variant',choices=list('ABCDEFGHI'))
    parser.add_argument('--split',choices=['debug','validation','holdout'],default='validation')
    parser.add_argument('--concurrency',type=int,default=4)
    parser.add_argument('--smoke',action='store_true',help='Mock protocol smoke only; never writes ablation scores')
    args=parser.parse_args()
    
    ready,reason=(True,None) if args.smoke else preflight()
    if not ready:
        dest=HERE/'results';dest.mkdir(exist_ok=True)
        (dest/'ablation_status.json').write_text(json.dumps({'status':'blocked_network','model_api_reachable':False,
            'error_type':reason,'scores_fabricated':False,'platform_uploads':0},indent=2)+'\n',encoding='utf-8')
        raise SystemExit('Model API is unreachable; real ablation metrics were not produced.')
    if args.variant:return run_variant(args)
    if args.split=='holdout':
        # Compare the frozen baseline and the frozen clean production design once.
        selection=json.loads((HERE/'results/selection.json').read_text(encoding='utf-8'))
        variants='A'+selection['selected_variant']
    else:variants='ABCDEFGHI'
    for variant in variants:
        command=[sys.executable,__file__,'--variant',variant,'--split',args.split,'--concurrency',str(args.concurrency)]
        if args.smoke:command.append('--smoke')
        subprocess.run(command,check=True)

if __name__=='__main__':main()
