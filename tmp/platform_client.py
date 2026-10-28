"""Course submission helper. Never prints login secrets or session cookies."""
import argparse
import json
from pathlib import Path
import zipfile
import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://10.1.0.220:9010'
SLUG = 'assignment3'

def session():
    credentials = json.loads((ROOT / '2024012348.token.json').read_text(encoding='utf-8-sig'))
    client = requests.Session()
    client.trust_env = False
    response = client.post(BASE + '/api/auth/student-login', json={
        'student_id': credentials['student_id'], 'token': credentials['token']}, timeout=20)
    response.raise_for_status()
    client.headers['X-CSRF-Token'] = response.json()['csrf_token']
    return client

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['status', 'submit', 'board'])
    parser.add_argument('--version', default='baseline')
    args = parser.parse_args()
    client = session()
    if args.action == 'submit':
        latest = client.get(f'{BASE}/api/assignments/{SLUG}/submissions/latest', timeout=20).json()
        if latest and latest['status'] in {'queued', 'preparing', 'installing', 'evaluating'}:
            print(json.dumps(latest, ensure_ascii=False)); return
        folder = ROOT / 'attack_defense_bot/attack_defense_bot'
        archive = ROOT / 'output' / f'course_{args.version}.zip'
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
            for path in sorted(folder.rglob('*')):
                if path.is_file() and '__pycache__' not in path.parts and path.suffix not in {'.pyc','.sqlite3','.sqlite3-journal'}:
                    package.write(path, 'attack_defense_bot/' + path.relative_to(folder).as_posix())
        with archive.open('rb') as stream:
            response = client.post(f'{BASE}/api/assignments/{SLUG}/submissions',
                                   files={'file': (archive.name, stream, 'application/zip')}, timeout=60)
        print('archive', archive, 'HTTP', response.status_code)
        print(response.text)
        if response.ok:
            record = dict(response.json(), version=args.version, archive=str(archive))
            (ROOT/'output'/f'submission_{args.version}.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    elif args.action == 'status':
        response = client.get(f'{BASE}/api/assignments/{SLUG}/submissions/latest', timeout=20)
        print(response.text)
        if response.ok:
            (ROOT/'output/latest_submission.json').write_text(json.dumps(response.json(),ensure_ascii=False,indent=2),encoding='utf-8')
            item = response.json()
            if item and item['status'] in {'success','failed'}:
                history_path = ROOT/'output/submission_history.json'
                history = json.loads(history_path.read_text(encoding='utf-8')) if history_path.exists() else []
                history = [x for x in history if x.get('id') != item['id']] + [item]
                history_path.write_text(json.dumps(history,ensure_ascii=False,indent=2),encoding='utf-8')
    else:
        result = client.get(f'{BASE}/api/assignments/{SLUG}/leaderboard', timeout=20).json()
        result['entries'] = result.get('entries', [])[:3] + [x for x in result.get('entries', [])[3:] if x.get('is_me')]
        print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
