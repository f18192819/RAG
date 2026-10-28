"""Download official security guidance and split by headings/paragraphs."""
import hashlib
import json
import re
from pathlib import Path
import requests
import fitz

ROOT=Path(__file__).resolve().parents[1]
FOLDER=ROOT/'attack_defense_bot/attack_defense_bot/knowledge'
SHEETS={
    'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet': 'CSRF防护令牌 跨站请求伪造 会话绑定 令牌不可预测 来源校验 SameSite',
    'SQL_Injection_Prevention_Cheat_Sheet': 'SQL注入 参数化查询 预编译 绑定参数 数据库权限',
    'Cross_Site_Scripting_Prevention_Cheat_Sheet': 'XSS防护 上下文输出编码 内容安全策略 HTML转义',
    'Password_Storage_Cheat_Sheet': '口令哈希 密码存储 Argon2id 盐值 工作因子',
    'Session_Management_Cheat_Sheet': '安全会话管理 会话标识 更新 会话过期 Cookie Secure HttpOnly SameSite',
    'Secrets_Management_Cheat_Sheet': '机密集中管理 应用凭据 短期凭据 轮换 密钥 Secrets management',
    'Transport_Layer_Security_Cheat_Sheet': '传输加密 TLS 证书 HTTPS 协议版本',
    'Logging_Cheat_Sheet': '集中日志关联 审计日志 SIEM 日志字段',
    'Vulnerability_Management_Cheat_Sheet': '漏洞管理闭环 修复优先级 资产关键性 修复验证 漏洞负责人',
    'Software_Supply_Chain_Security_Cheat_Sheet': '软件成分分析 软件物料清单 SCA SBOM 依赖扫描',
}

def chunks(text, limit=1500):
    block=''
    for paragraph in re.split(r'\n\s*\n',text):
        paragraph=paragraph.strip()
        if not paragraph: continue
        if len(block)+len(paragraph)>limit and block:
            yield block;block=''
        if len(paragraph)>limit:
            for start in range(0,len(paragraph),limit-150):
                yield paragraph[start:start+limit]
        else:
            block += ('\n\n' if block else '')+paragraph
    if block:yield block

def main():
    rows=[]
    for slug,aliases in SHEETS.items():
        url=f'https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/{slug}.md'
        response=requests.get(url,timeout=30)
        if not response.ok:
            print(slug,response.status_code);continue
        text=response.text
        title=slug.replace('_',' ')
        sections=re.split(r'(?m)(?=^## )',text)
        for section in sections:
            heading=section.splitlines()[0].lstrip('# ').strip()
            cleaned=re.sub(r'!\[[^\]]*\]\([^)]*\)','',section)
            cleaned=re.sub(r'\[([^\]]+)\]\([^)]*\)',r'\1',cleaned)
            for i,chunk in enumerate(chunks(cleaned)):
                if len(chunk)<80:continue
                identifier=hashlib.sha256((slug+heading+str(i)).encode()).hexdigest()[:12]
                rows.append({'id':'owasp-'+identifier,'title':title+' / '+heading,'aliases':aliases,
                             'text':f'Source context: OWASP {title}; section {heading}.\n'+chunk,
                             'source':f'https://cheatsheetseries.owasp.org/cheatsheets/{slug}.html'})
        print(slug,'OK')
    url='https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-111.pdf'
    response=requests.get(url,timeout=30);response.raise_for_status()
    doc=fitz.open(stream=response.content,filetype='pdf')
    for page_no,page in enumerate(doc):
        if page_no<7:continue
        for i,chunk in enumerate(chunks(page.get_text())):
            rows.append({'id':f'nist-800111-p{page_no+1}-{i}',
                         'title':'NIST SP 800-111 storage encryption: full disk encryption, authentication and key management',
                         'aliases':'全盘加密 磁盘加密 启动前保护 恢复密钥 FDE pre-boot authentication recovery key',
                         'text':chunk,'source':'https://csrc.nist.gov/pubs/sp/800/111/final'})
    (FOLDER/'additional_guidance.json').write_text(json.dumps({'retrieved':'2026-10-28','documents':rows},ensure_ascii=False),encoding='utf-8')
    print('Total additional source chunks',len(rows))

if __name__=='__main__':main()
