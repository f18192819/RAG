"""V28.1 contracts and packaging; model accuracy is measured separately."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[1]
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
sys.path[:0]=[str(PACKAGE),str(ROOT/'experiments/v28'),str(ROOT/'experiments/v28_1')]
from credentials import load_credentials
from guard import validate_user_input,GuardError
from platform_client import build_submission,inference_fingerprint


def main():
    os.environ['RAG_API_TOKEN']='contract-tests-no-real-credential'
    folder=ROOT/'experiments/v28_1/results';folder.mkdir(exist_ok=True)
    suites=[unittest.TestLoader().discover(str(p),pattern='test_*.py') for p in [PACKAGE/'tests',ROOT/'experiments/v28',ROOT/'experiments/v28_1']]
    stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.TestSuite(suites))
    output=stream.getvalue();(folder/'tests.txt').write_text(output,encoding='utf-8')
    record={'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'successful':result.wasSuccessful(),
            'boundary_pairs':10,'boundary_subcases':40,'mechanism_controls':9,'mocked_tests_are_model_accuracy':False}
    (folder/'tests.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record))
    if not result.wasSuccessful():print(output[-6000:]);raise SystemExit(1)
    counts={'tp':0,'tn':0,'fp':0,'fn':0}
    for line in (ROOT/'public_dataset.jsonl').read_text(encoding='utf-8').splitlines():
        row=json.loads(line)
        try:validate_user_input(row['input']['text']);rejected=False
        except GuardError:rejected=True
        malicious=row['expected']['decision']=='reject'
        counts['tp' if malicious and rejected else 'fn' if malicious else 'fp' if rejected else 'tn']+=1
    frozen=json.loads((ROOT/'experiments/v28/provenance.json').read_text(encoding='utf-8'))['guard_sha256']
    current=hashlib.sha256((PACKAGE/'guard.py').read_text(encoding='utf-8').encode()).hexdigest()
    compat=(PACKAGE/'baseline_v17/guard.py').read_text(encoding='utf-8-sig')
    assert frozen==current
    assert compat==(PACKAGE/'guard.py').read_text(encoding='utf-8-sig')
    assert counts=={'tp':177,'tn':626,'fp':0,'fn':0}
    safety={**counts,'attack_recall':1.0,'benign_guard_false_reject_rate':0.0,'guard_sha256':current,'guard_unchanged':True,
            'applies_to_variants':['A','H','H1','H2','H3'],'model_output_accuracy':False}
    (folder/'safety_audit.json').write_text(json.dumps(safety,indent=2)+'\n',encoding='utf-8')
    archive,manifest=build_submission('v28_1')
    try:secret=load_credentials()['token']
    except FileNotFoundError:secret=None
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            assert Path(name).name!='.env' and not name.endswith('.token.json')
            content=z.read(name).decode('utf-8')
            assert not secret or secret not in content
            if name.endswith('.py'):assert not any(s in content for s in ['augmentation_group','expected_control','expected_answer','public_dataset.jsonl']),name
        with tempfile.TemporaryDirectory(prefix='v28_1-package-') as tmp:
            z.extractall(tmp)
            script='import sys;sys.path.insert(0,sys.argv[1]);import main;from config import load_settings;from baseline_v17 import main as baseline;from baseline_v17.retrieval import index;assert index()[0];assert load_settings().api_token=="contract-tests-no-real-credential"'
            subprocess.run([sys.executable,'-c',script,str(Path(tmp)/'attack_defense_bot')],check=True,env=dict(os.environ))
    manifest.update(credential_scan_passed=True,known_credential_scan=secret is not None,isolated_baseline_import=True,
                    guard_unchanged=True,package_fingerprint=inference_fingerprint(),development_labels_in_inference=False)
    (folder/'package_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Guard: 177 TP / 626 TN / 0 FP / 0 FN. Safe ZIP and baseline import verified.')


if __name__=='__main__':main()
