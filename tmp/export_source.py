"""Export an exact submitted version for sharing without its private .env."""
import argparse
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--version',required=True)
    args=parser.parse_args()
    source=ROOT/'output'/f'course_{args.version}.zip'
    target=ROOT/'output'/f'2024012348_source_{args.version}.zip'
    credentials=json.loads((ROOT/'2024012348.token.json').read_text(encoding='utf-8-sig'))
    secret=credentials['token'].encode()
    count=0
    with zipfile.ZipFile(source) as submitted,zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as exported:
        safe_keys={'RAG_API_BASE_URL','RAG_DATABASE_NAME','RAG_PERSONAL_DATABASE','RAG_METRIC_TYPE',
                   'RAG_TOP_K','RAG_SCORE_THRESHOLD','RAG_CONTEXT_MAX_FILES','RAG_CONTEXT_MAX_CHARS',
                   'RAG_TIMEOUT_SECONDS','RAG_TEMPERATURE','RAG_MAX_TOKENS','RAG_CHOICE_STRATEGY'}
        safe_values={}
        for line in submitted.read('attack_defense_bot/.env').decode('utf-8-sig').splitlines():
            if '=' in line:
                key,value=line.split('=',1)
                if key in safe_keys:safe_values[key]=value
        for name in submitted.namelist():
            if name.endswith('/.env'):continue
            data=submitted.read(name)
            if name.endswith('/.env.example'):
                lines=[]
                for line in data.decode('utf-8-sig').splitlines():
                    key=line.split('=',1)[0]
                    lines.append(key+'='+safe_values[key] if key in safe_values else line)
                data=('\n'.join(lines)+'\n').encode()
            if secret in data:raise RuntimeError('Credential found in source export')
            exported.writestr(name,data);count+=1
    print(json.dumps({'output':str(target),'files':count,'private_env_removed':True},ensure_ascii=False))

if __name__=='__main__':main()
