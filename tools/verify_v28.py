"""Run contracts, guard audit, packaging and credential-leak checks locally."""
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
sys.path[:0]=[str(PACKAGE),str(ROOT/'experiments/v28')]
from credentials import load_credentials
from platform_client import build_submission,INFERENCE


def main():
    os.environ['RAG_API_TOKEN']='contract-tests-no-real-credential'
    result_dir=ROOT/'experiments/v28/results';result_dir.mkdir(exist_ok=True)
    suites=[]
    for directory in [PACKAGE/'tests',ROOT/'experiments/v28']:
        suites.append(unittest.TestLoader().discover(str(directory),pattern='test_*.py'))
    stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.TestSuite(suites))
    output=stream.getvalue();(result_dir/'tests.txt').write_text(output,encoding='utf-8')
    record={'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'successful':result.wasSuccessful(),'boundary_pairs':10,'boundary_production_subcases':40,
            'mocked_results_are_model_accuracy':False}
    (result_dir/'tests.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record))
    if not result.wasSuccessful():
        print(output[-6000:]);raise SystemExit(1)
    subprocess.run([sys.executable,str(ROOT/'experiments/v28/eval_offline.py')],check=True)
    archive,manifest=build_submission('v28_clean')
    try:secret=load_credentials()['token']
    except FileNotFoundError:secret=None
    with zipfile.ZipFile(archive) as package:
        names=package.namelist()
        assert not any(Path(name).name=='.env' or name.endswith('.token.json') for name in names)
        for name in names:
            data=package.read(name).decode('utf-8')
            assert not secret or secret not in data,'Credential-like content found; value was not printed'
            if name.endswith('.py'):
                assert not any(marker in data for marker in ['augmentation_group','expected_control','expected_answer','public_dataset.jsonl']),name
        with tempfile.TemporaryDirectory(prefix='v28-import-') as directory:
            destination=Path(directory).resolve()
            assert destination.parent==Path(tempfile.gettempdir()).resolve()
            assert all('..' not in Path(name).parts and not Path(name).is_absolute() for name in names)
            package.extractall(destination)
            env=dict(os.environ,RAG_API_TOKEN='package-contract-test')
            subprocess.run([sys.executable,'-c','import sys;sys.path.insert(0,sys.argv[1]);import main;from config import load_settings;assert load_settings().api_token=="package-contract-test"',str(destination/'attack_defense_bot')],env=env,check=True)
    frozen=json.loads((ROOT/'experiments/v28/provenance.json').read_text(encoding='utf-8'))
    current=(PACKAGE/'guard.py').read_text(encoding='utf-8')
    manifest.update(credential_scan_passed=True,development_labels_in_inference=False,
                    known_credential_literal_check=secret is not None,
                    original_guard_unchanged=hashlib.sha256(current.encode('utf-8')).hexdigest()==frozen['guard_sha256'],isolated_package_import=True)
    assert manifest['original_guard_unchanged']
    (result_dir/'package_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Safe inference ZIP built and imported; guard unchanged; no credentials or development labels included.')

if __name__=='__main__':main()
