import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
PACKAGE=ROOT/'attack_defense_bot/attack_defense_bot'
REPAIRS={
    '胡椒':'pepper（额外机密）', '访问证书':'访问权限复核凭证',
    '陈旧报告':'漏洞超期报告', '库存':'资产清单',
    '配置、转移、审查和及时取消配置':'账户开通、岗位变更、权限复核和及时撤权',
    '预置/取消预置':'账户开通和撤权',
    '有限时间提升':'限时提权', '拥有者':'负责人', '所有者':'负责人',
    '审查员':'审核人员', '到期强制执行':'到期自动回收',
    '具有跟踪的负责人和截止日期':'明确负责人并跟踪整改期限',
    '固定抵抗':'抵御会话固定攻击', '测试旋转':'测试凭据轮换',
    '初步诊断所有权':'告警研判负责人', '负责负责人':'明确负责人',
    '发布门':'发布门禁', '单次延迟的渗透测试':'开发末期的一次渗透测试',
    '可靠的摄入':'可靠的日志采集', '受保护的保留':'受保护的日志留存',
    '分类工作流程':'告警研判流程', '媒体和敏感性':'介质类型和敏感度',
    '补救':'整改', '管辖权':'司法辖区', '违规通知':'数据泄露通知',
    '包络加密':'信封加密', '逃脱抗性':'抗逃逸能力', '测量启动':'度量启动',
    '测试代表恢复':'测试代表性恢复场景', '修复空缺':'修复缺口',
    '未经验证的恢复备份':'未经恢复验证的备份',
    '禁止单位转移':'禁止的数据传输', '有限的删除':'限制删除权限',
}
MANUAL={
    'guide-data-classification':'数据分类应把处置、存储、访问、传输、保留和销毁规则映射到相应敏感级别。对照实际数据检验标签，培训使用者，并周期复核分类范围及准确性。',
    'guide-backup':'不可变备份需要受保护的保留设置、备份作业监控和重复恢复测试。通过代表性数据验证恢复时间目标和恢复点目标，不能仅凭备份任务成功状态判断可恢复性。',
    'guide-awareness':'安全意识需要结合岗位实践、事件上报流程和反馈不断强化。衡量上报质量、重复错误与后续改进情况，不能只统计培训出勤。',
    'guide-identity':'身份生命周期管理把账户开通、岗位变更、访问复核和及时撤权与明确负责人关联。证据包括审批请求、权限复核记录和撤销记录。',
    'guide-password':'使用 Argon2id 等专用口令哈希函数，为每个口令配置唯一随机盐和经过校准的工作因子；单独保护的 pepper（额外机密）可作为补充。验证参数，随硬件和威胁变化升级。',
    'guide-tls':'部署受支持的TLS协议与密码算法，严格校验证书链和主机名，保护私钥并监控到期。客户端应拒绝伪造、不可信、过期或主机名不匹配的证书，防止冒充服务和中间人攻击；验证正常及拒绝路径。',
    'guide-csrf':'CSRF令牌必须保密、不可预测并与会话绑定。校验Origin或Referer来源以及适当的SameSite Cookie提供纵深防御；GET请求不应改变状态。',
    'guide-ndr':'NDR需要覆盖关键网络边界和东西向链路，建立正常流量基线，并关联资产与身份信息。分析人员调查告警、收集证据并执行经过测试的遏制流程；加密流量仍可提供有价值的元数据。',
    'guide-key':'密钥需要强随机性、适当的KMS或HSM保护、职责分离及审计能力。测试密钥轮换、恢复和吊销，并覆盖依赖系统及加密数据的访问。',
    'guide-ddos':'DDoS防护在关键资源耗尽前过滤或吸收恶意流量，结合上游协作、资源配额、速率限制与经过测试的故障切换。建立正常流量基线，调优阈值并演练响应，避免阻断正常业务。',
    'guide-endpoint-privilege':'移除不必要的本地管理员权限，分离管理身份与日常身份，经审批后按任务限时提权。监控高权限操作、复核例外，并测试日常应用在不具备多余权限时能否正常运行。',
    'guide-memory':'内存安全语言预防多类内存破坏；ASLR、不可执行内存及栈保护降低遗留不安全组件的可利用性。尽量减少不安全接口，对解析器进行测试并验证编译加固设置。缓解机制不能修复底层缺陷。',
}

def main():
    rows=[json.loads(line) for line in (ROOT/'tmp/translated_guides.jsonl').read_text(encoding='utf-8').splitlines()]
    translations={row['id']:row for row in rows}
    for name in ['control_guides.json','technical_guides.json']:
        path=PACKAGE/'knowledge'/name
        data=json.loads(path.read_text(encoding='utf-8'))
        for doc in data['documents']:
            parts=re.split(r'(?<=[。])\s*(?=[A-Za-z])',doc['text'],maxsplit=1)
            row=translations.get(doc['id'],{'translation':'','english':parts[-1]})
            original=re.split(r'(?<=[。])\s*(?=[A-Za-z])',doc['text'],maxsplit=1)[0]
            translation=MANUAL.get(doc['id'],row['translation'])
            if translation.startswith('{'):
                translation=json.loads(translation)['text']
            if not translation:
                raise ValueError('Missing translation: '+doc['id'])
            if re.search(r'SOURCE_AS_DATA|translation|仅返回JSON|保留所有安全机制|不要总结',translation):
                raise ValueError('Translation requires review: '+doc['id'])
            chinese=original+' '+translation
            for before,after in REPAIRS.items():chinese=chinese.replace(before,after)
            doc['text_zh']=chinese
            doc['text_en']=row['english']
            if doc['id']=='guide-tls':
                doc['text_en']+=' Strict certificate validation prevents clients from connecting to impersonated servers or an intermediary using an untrusted certificate.'
            doc['text']=chinese+'\n'+doc['text_en']
        path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Applied complete bilingual notes:',len(rows))

if __name__=='__main__':main()
