"""Build the concise report and clean improved-code submission for 2026-10-25."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'attack_defense_bot/attack_defense_bot'
LABEL = '2024012348房楷涵'
DEST = ROOT / 'output' / LABEL
TEMP = ROOT / 'tmp/pdfs/improved_homework'
EXTRACT = TEMP / 'extracted'
CODE_ZIP = DEST / '2024012348_改进代码.zip'
MD = DEST / '2024012348_改进进度报告.md'
PDF = DEST / '2024012348_改进进度报告.pdf'
OUTER = ROOT / 'output' / (LABEL + '.zip')

README = '''# 安全 RAG 助手（改进版）

姓名：房楷涵　学号：2024012348

## 运行

使用 Python 3.10 或更新版本，连接校园网或课程 VPN，在本目录执行：

```powershell
python -m pip install -r requirements.txt
python setup_token.py --token-file "C:\\路径\\2024012348.token.json"
python main.py --query "什么是最小权限原则？"
```

也可复制 `.env.example` 为 `.env` 后填写 `RAG_API_TOKEN`。环境变量优先于 `.env`；代码包不附带个人 Token。
默认检索只读公共库 `common_dataset`，单次问答不需要本地公开数据集。程序输出包含 `decision`、`answer`、`evidence`、`explanation` 的 JSON。

## 实现

`main.py` 串联输入校验、检索、上下文整理、提示词构建、模型生成和输出校验。
`guard.py` 处理规范化、组合风险规则、模板检查和响应检查；`prompt_builder.py` 转义外部数据并定义固定输出约束。
`data_processor.py` 负责污染段落清理、去重、轻量重排、字符预算和引用对齐。
`api_client.py`、`config.py` 负责接口调用、参数校验、凭据脱敏及内网代理处理。

## 验证与复现

```powershell
python -m unittest discover -s tests -v
python eval_offline.py --dataset "C:\\路径\\public_dataset.jsonl" --output-dir output/offline
python smoke_api.py --output output/api_smoke.json
python eval_dataset.py --dataset "C:\\路径\\public_dataset.jsonl" --concurrency 5 --short-answer-policy concepts --short-answer-concept-threshold 0.5 --progress-every 25 --output-dir output/full_online
```

本次打包从解压后的代码执行离线测试。历史在线全量评估完成于 2026-10-18，指标见同交的进度报告；2026-10-25 未重跑在线全量评估。
`eval_offline.py` 中保留的 baseline 关键词统计仅用于比较输入护栏，不是另一套原始课程实现。
`smoke_api.py` 会创建或复用个人演示库并上传自编摘要；不会写入或删除公共库。
公开集参与过开发，成绩不代表隐藏集。引用范围检查不能保证资料在语义上支持答案，多轮记忆模块保留但主链路未启用。
'''

def ensure_dirs():
    DEST.mkdir(parents=True, exist_ok=True)
    TEMP.mkdir(parents=True, exist_ok=True)

def secret_value():
    obj = json.loads((ROOT/'2024012348.token.json').read_text(encoding='utf-8-sig'))
    assert str(obj['student_id']) == '2024012348'
    return obj['token']

def prepare():
    ensure_dirs()
    allowed = []
    for p in sorted(SOURCE.rglob('*')):
        if not p.is_file():
            continue
        rel = p.relative_to(SOURCE)
        if '__pycache__' in rel.parts or p.suffix in {'.pyc','.pyo','.zip'} or p.name == '.env':
            continue
        if p.suffix == '.py' or p.name in {'.env.example','.gitignore','requirements.txt','README.md'}:
            allowed.append((p, rel.as_posix()))
    py = [(p,n) for p,n in allowed if p.suffix=='.py']
    assert len(py)==14
    assert any(n=='tests/test_security.py' for p,n in py)
    secret = secret_value().encode('utf-8')
    source_hashes = {n:hashlib.sha256(p.read_bytes()).hexdigest() for p,n in py}
    with zipfile.ZipFile(CODE_ZIP, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for p,n in allowed:
            data = README.encode('utf-8') if n == 'README.md' else p.read_bytes()
            assert secret not in data, 'Credential would enter the submission'
            z.writestr('attack_defense_bot/'+n, data)
    with zipfile.ZipFile(CODE_ZIP) as z:
        assert z.testzip() is None
        assert all(n.startswith('attack_defense_bot/') and '..' not in Path(n).parts for n in z.namelist())
        assert all(not n.endswith('/.env') and '__pycache__' not in n for n in z.namelist())
        z.extractall(EXTRACT)
    env = os.environ.copy()
    env.update(PYTHONIOENCODING='utf-8',PYTHONDONTWRITEBYTECODE='1')
    cwd = EXTRACT/'attack_defense_bot'
    test = subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-v'],
                          cwd=cwd,env=env,capture_output=True,text=True,encoding='utf-8')
    log = test.stdout+'\n'+test.stderr
    (TEMP/'unittest.txt').write_text(log,encoding='utf-8')
    assert test.returncode==0 and re.search(r'Ran 14 tests',log) and re.search(r'\bOK\b',log),log
    offline = subprocess.run([sys.executable,'-B','eval_offline.py','--dataset',str(ROOT/'public_dataset.jsonl'),
                              '--output-dir',str(TEMP/'offline')],cwd=cwd,env=env,
                             capture_output=True,text=True,encoding='utf-8')
    assert offline.returncode==0,offline.stderr
    guard = json.loads((TEMP/'offline/guard_summary.json').read_text(encoding='utf-8'))
    assert guard['dataset_records']==803
    assert (guard['improved']['tp'],guard['improved']['fp'],guard['improved']['fn'],guard['improved']['tn'])==(177,0,0,626)
    for n,digest in source_hashes.items():
        assert hashlib.sha256((cwd/n).read_bytes()).hexdigest()==digest
    historical = (ROOT/'output/submission/2024012348_进展报告.md').read_text(encoding='utf-8')
    for expected in ['90.16%（724 / 803）','87.38%（547 / 626）','100.00%（177 / 177）']:
        assert expected in historical
    checks = {'student_id':'2024012348','name':'房楷涵','date':'2026-10-25',
              'source_sha256':source_hashes,'python_files':len(py),'package_files':len(allowed),
              'unittest_passed':14,'guard_records':803,'guard_attack_blocked':177,'guard_false_blocked':0,
              'historical_online_date':'2026-10-18','online_full_rerun_this_week':False,
              'code_zip_sha256':hashlib.sha256(CODE_ZIP.read_bytes()).hexdigest()}
    (TEMP/'checks.json').write_text(json.dumps(checks,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Clean improved code ZIP: %d files, 14 unchanged Python sources.' % len(allowed))
    print('Extracted-package unittest: 14/14 passed; offline guard: 177/177 attacks blocked, 0/626 normal false blocks.')

def report():
    ensure_dirs()
    checks = json.loads((TEMP/'checks.json').read_text(encoding='utf-8'))
    assert checks['unittest_passed']==14 and checks['online_full_rerun_this_week'] is False
    chain = '输入校验 → 公共库检索 → 材料整理 → 提示词构建 → 模型生成 → 输出校验。'
    design = '保留课程接口，将防护放在输入、检索材料、提示词和输出四个环节。检索侧选择少量相关资料并限制上下文长度，引用与实际使用的材料保持一致；提示词侧区分应用规则和外部数据，减少资料中的指令对任务的干扰。'
    decision = '正常知识问题在资料不足时说明依据并尽力回答；要求越权、泄露或绕过检查的请求予以拒绝，避免把知识不足当作安全拒答。'
    credit = '代码实现与自动化测试使用 AI 辅助完成。'
    changes = [
        ['输入与输出防护','规范化输入，增加组合风险规则；检查 JSON、拒答字段及引用范围，拦截敏感输出。'],
        ['提示词隔离','对问题、资料和来源标签转义；完整检查固定模板，防止伪造边界。'],
        ['检索与引用','清洗污染段落、去重和轻量重排；统一字符预算，按实际材料生成引用。'],
        ['接口与配置','校验参数，隐藏 Token 并脱敏错误；内网请求默认绕过环境代理。'],
    ]
    results = [
        ['公开集总正确率','90.16%（724 / 803）'],
        ['正常知识题正确率','87.38%（547 / 626）'],
        ['攻击拒答率','100.00%（177 / 177）'],
        ['正常题误拒 / 接口错误','0 / 0'],
    ]
    tested = '10 月 18 日已跑通上传、检索和对话等 9 项真实接口验证，并完成 803 条公开集评估。此次从新代码包解压复核，14 项离线测试全部通过；输入护栏拦截 177 条攻击，626 条正常题均放行。'
    limitation = '表中在线成绩沿用 10 月 18 日记录，本周未重跑在线全量评估。公开集参与了开发，隐藏集效果和引用的语义支持度尚未验证。'
    plan = '使用 Python 3.10+，安装依赖并在本地配置 Token 后运行 main.py，具体命令见代码包 README。下一步复核 79 条错题，改善检索相关性与简答题覆盖，并检查引用是否支持答案。'
    def mt(headers,body):
        return '| '+' | '.join(headers)+' |\n| '+' | '.join(['---']*len(headers))+' |\n'+'\n'.join('| '+' | '.join(row)+' |' for row in body)
    md = '\n\n'.join([
        '# 安全 RAG 助手改进进度报告',
        '姓名：房楷涵　学号：2024012348　日期：2026-10-25',
        '## 1. 架构与思路设计（本人设计）',chain,design,decision,credit,
        '## 2. 本次代码改进',mt(['改进项','实现内容'],changes),
        '## 3. 验证结果',tested,mt(['指标','在线实测结果'],results),limitation,
        '## 4. 运行与后续工作',plan])+'\n'
    MD.write_text(md,encoding='utf-8')

    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.colors import HexColor
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import fitz
    pdfmetrics.registerFont(TTFont('Song','C:/Windows/Fonts/simsun.ttc',subfontIndex=0))
    pdfmetrics.registerFont(TTFont('Hei','C:/Windows/Fonts/simhei.ttf'))
    style = {
        'title':ParagraphStyle('Title',fontName='Hei',fontSize=16,leading=24,alignment=TA_CENTER,spaceAfter=5),
        'meta':ParagraphStyle('Meta',fontName='Song',fontSize=10,leading=15,alignment=TA_CENTER,spaceAfter=7),
        'heading':ParagraphStyle('Heading',fontName='Hei',fontSize=11.5,leading=17,spaceBefore=7,spaceAfter=4),
        'body':ParagraphStyle('Body',fontName='Song',fontSize=10.5,leading=16,spaceAfter=4,wordWrap='CJK'),
        'cell':ParagraphStyle('Cell',fontName='Song',fontSize=10,leading=14.5,wordWrap='CJK'),
        'th':ParagraphStyle('TH',fontName='Hei',fontSize=10,leading=14.5,wordWrap='CJK'),
    }
    story = []
    def p(value,kind='body'):
        story.append(Paragraph(escape(value),style[kind]))
    def table(headers,body,widths):
        data = [[Paragraph(escape(x),style['th']) for x in headers]]
        data += [[Paragraph(escape(x),style['cell']) for x in row] for row in body]
        t = Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([
            ('GRID',(0,0),(-1,-1),0.4,HexColor('#888888')),
            ('BACKGROUND',(0,0),(-1,0),HexColor('#F2F2F2')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
            ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
        ]))
        story.extend([t,Spacer(1,4)])
    p('安全 RAG 助手改进进度报告','title')
    p('姓名：房楷涵　学号：2024012348　日期：2026-10-25','meta')
    p('1. 架构与思路设计（本人设计）','heading')
    p(chain);p(design);p(decision);p(credit)
    p('2. 本次代码改进','heading');table(['改进项','实现内容'],changes,[100,385])
    p('3. 验证结果','heading');p(tested)
    table(['指标','在线实测结果'],results,[210,275]);p(limitation)
    p('4. 运行与后续工作','heading');p(plan)
    doc = SimpleDocTemplate(str(PDF),pagesize=(595.28,841.89),leftMargin=55,rightMargin=55,topMargin=42,bottomMargin=40,
                            title='安全 RAG 助手改进进度报告',author='房楷涵')
    def footer(canvas,doc):
        canvas.setFont('Song',9)
        canvas.drawCentredString(297.64,22,str(doc.page))
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    d = fitz.open(PDF)
    for i,page in enumerate(d):
        page.get_pixmap(matrix=fitz.Matrix(1.5,1.5)).save(TEMP/f'report-page-{i+1}.png')
    assert len(d)==1, f'Expected a concise single page; got {len(d)} pages'
    text = ''.join(page.get_text() for page in d)
    for expected in ['本人设计','724 / 803','547 / 626','177 / 177','2026-10-25']:
        assert expected in text,expected
    assert secret_value() not in md and secret_value() not in text
    print('Report written: one PDF page and matching Markdown.')

def bundle():
    ensure_dirs()
    import fitz
    assert MD.is_file() and PDF.is_file() and CODE_ZIP.is_file()
    assert {p.name for p in DEST.iterdir()}=={MD.name,PDF.name,CODE_ZIP.name}
    secret = secret_value().encode('utf-8')
    checks = json.loads((TEMP/'checks.json').read_text(encoding='utf-8'))
    with zipfile.ZipFile(CODE_ZIP) as z:
        assert z.testzip() is None
        for name in z.namelist():
            assert '__pycache__' not in name and not name.endswith(('.pyc','.pyo','/.env'))
            data = z.read(name)
            assert secret not in data
        for name,digest in checks['source_sha256'].items():
            assert hashlib.sha256(z.read('attack_defense_bot/'+name)).hexdigest()==digest
            assert hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()==digest
        assert '当前网络连接课程接口超时' not in z.read('attack_defense_bot/README.md').decode('utf-8')
    pdf = fitz.open(PDF)
    assert len(pdf)==1
    assert secret.decode('utf-8') not in ''.join(p.get_text() for p in pdf)
    with zipfile.ZipFile(OUTER,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for file in [CODE_ZIP,MD,PDF]:
            z.write(file,arcname=file.name)
    with zipfile.ZipFile(OUTER) as z:
        assert z.testzip() is None and len(z.namelist())==3
        for file in [CODE_ZIP,MD,PDF]:
            assert z.read(file.name)==file.read_bytes()
        with zipfile.ZipFile(io.BytesIO(z.read(CODE_ZIP.name))) as inner:
            assert inner.testzip() is None
    checks['outer_archive_sha256'] = hashlib.sha256(OUTER.read_bytes()).hexdigest()
    checks['report_pages'] = len(pdf)
    checks['folder'] = str(DEST)
    checks['outer_archive'] = str(OUTER)
    (TEMP/'checks.json').write_text(json.dumps(checks,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'folder':str(DEST),'submission_zip':str(OUTER),
                      'files':[{ 'name':p.name,'bytes':p.stat().st_size} for p in DEST.iterdir()]},ensure_ascii=False,indent=2))

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('step',choices=['prepare','report','bundle'])
    step=parser.parse_args().step
    {'prepare':prepare,'report':report,'bundle':bundle}[step]()
