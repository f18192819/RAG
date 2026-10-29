"""Configure an external credential path without copying the credential."""
import argparse
from pathlib import Path


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--token-file',type=Path,required=True)
    args=parser.parse_args();location=args.token_file.expanduser().resolve()
    repository=Path(__file__).resolve().parents[2]
    if location.is_relative_to(repository):raise SystemExit('Credential file must be outside the repository')
    if not location.is_file():raise SystemExit('External credential file does not exist')
    target=Path(__file__).resolve().parent/'.env'
    lines=target.read_text(encoding='utf-8-sig').splitlines() if target.exists() else []
    lines=[line for line in lines if not line.startswith(('RAG_API_TOKEN=','RAG_TOKEN_FILE='))]
    lines.append('RAG_TOKEN_FILE='+str(location))
    target.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('External credential path configured. No credential was copied or displayed.')

if __name__=='__main__':main()
