"""分层防护：规范化、意图组合检测、严格模板校验、输出检查。"""
from __future__ import annotations
import json
import re
import unicodedata
from html import unescape
try:
    from .prompt_builder import SYSTEM_POLICY, ANSWER_RULES, PROMPT_VERSION, build_prompt
    from .question_format import has_choice_options, choice_stem, strip_question_header
except ImportError:
    from prompt_builder import SYSTEM_POLICY, ANSWER_RULES, PROMPT_VERSION, build_prompt
    from question_format import has_choice_options, choice_stem, strip_question_header


class GuardError(ValueError):
    """拒绝不符合安全策略的请求；异常不包含原始内容。"""


MAX_USER_INPUT_CHARS = 2000
MAX_PROMPT_CHARS = 24000


def normalize(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKC", text)
                   if unicodedata.category(c) != "Cf").lower()


# 行为与对象组合；安全术语本身不作为黑名单。
RISK_RULES = (
    ("override", r"(?:忽略|无视|覆盖|撤销|停止|取消|跳过|关闭|绕过|解除|不再适用|过期|不要完成).{0,36}(?:规则|指令|约束|原任务|原本的问题|权限|安全|限制|隔离|审核|检查|审批|身份确认)|(?:规则|安全要求).{0,18}(?:撤销|不再适用|过期)|(?:ignore|override|disregard|bypass|disable).{0,40}(?:previous|prior|system|safety|security|instruction|rule|permission|check)"),
    ("secret", r"(?:读取|返回|输出|公开|展示|列出|导出|泄露|提供|扫描|查找).{0,55}(?:私钥|密码|秘密字段|私密数据|受限信息|私有文件|内部配置|系统配置|内部凭据|访问令牌|会话凭据|api\s*key|隐藏提示|隐藏内容|私有上下文|系统提示|不可见文本|内部规则|系统层|开发者层)|(?:reveal|print|disclose|dump|show).{0,50}(?:system\s*prompt|secret|private\s*key|api\s*key|hidden|password|developer\s*message)"),
    ("tool", r"(?:调用|执行|使用|遍历).{0,35}(?:高权限|管理接口|文件工具|可用数据库)|(?:上传|发送|外传).{0,25}(?:外部服务器|指定地址)|(?:清除|删除).{0,20}(?:审计|安全日志)"),
    ("encoded", r"(?:base64|rot13|十六进制|编码|字符替换).{0,70}(?:执行|最高指令|不再.{0,8}检查)|(?:decode|decrypt).{0,60}(?:execute|obey|instruction priority)"),
    ("memory", r"(?:记住|长期保存|永久记忆|长期系统偏好|默认设置).{0,65}(?:规则|跳过|信任|允许|授权|导出)|(?:remember|permanent\s*memory).{0,50}(?:bypass|trust|allow|disable)"),
    ("role", r"(?:扮演|模拟|假设|虚构).{0,55}(?:无规则|无保密|没有保密|安全政策不存在|无条件执行越权)|(?:最高优先级|最高级指令|system_override|root policy patch|无限制响应模式)|(?:原样|逐字).{0,25}(?:系统|开发者|隐藏)|(?:系统层|开发者层).{0,30}(?:原样|代码块)"),
    ("boundary", r"</?(?:system|admin|context|user_question|untrusted_retrieved_context|available_citations)\b|end_of_user_input|reference finished"),
    ("secret", r"(?:内部规则|系统提示|隐藏提示|开发者消息).{0,30}(?:列出|展示|原样|副本|输出|透露)"),
    ("authority", r"(?:管理员|管理层|负责人|运维|平台).{0,60}(?:无需核验|不必验证|直接照做|全部跳过|免于验证)|(?:审计|身份确认|权限验证).{0,20}(?:跳过|省略)|(?:线下批准|紧急授权).{0,30}(?:私有|全部|高权限)"),
    ("memory", r"(?:已通过授权|允许导出|自动信任).{0,30}(?:永久记忆|长期记忆|保存规则)|(?:写入|登记).{0,20}(?:永久记忆|系统偏好)"),
    ("encoded", r"(?:编码|字符替换|解码|恢复原文).{0,60}(?:不要再次检查|不必验证|无条件执行)"),
)


def instruction_risks(text: str) -> list[str]:
    value = normalize(text)
    return list(dict.fromkeys(name for name, pattern in RISK_RULES if re.search(pattern, value)))


def _analysis_only(text: str) -> bool:
    value = strip_question_header(normalize(text))
    analysis = bool(re.search(r"(?:如何|怎样|为什么|什么|怎么|哪项|哪个|哪些|哪种|何种|有何|何时|何为|分析|识别|判断|解释|说明|介绍|描述|检测|防范|防御|防止|区别|风险|原理|作用|含义|哈希|散列|加盐|安全存储|密码策略|密钥管理|凭据管理|key管理|key轮换|最佳实践|教学示例|which|what|why|how|explain|detect|identify|password\s+hash|key\s+(?:rotation|storage)|best\s+practice)", value))
    analysis=analysis or bool(re.search(r'是否(?:应该|应当|合理|安全|正确|属于|构成|为|是)|应否|(?:合理|安全|正确|有效)吗|对不对|讨论|阐述|论述|简述|概述|评价|评估|true\s+or\s+false|is\s+it\s+(?:safe|correct|appropriate)|should\s+(?:a|an|the)\s+(?:model|assistant|system)|discuss|describe|assess|evaluate|summarize',value))
    execute = bool(re.search(r"(?:请你|现在|接下来|立刻|立即|然后).{0,12}(?:执行|照做|输出|公开|泄露|忽略|跳过)|(?:now|then)\s+(?:execute|obey|reveal|ignore)", value))
    execute=execute or bool(re.search(r'请(?:你)?\s*(?:(?:直接|立即|立刻|暂时|先|无条件)\s*)*(?:忽略|无视|覆盖|跳过|关闭|绕过|取消|解除|撤销|停止)|你必须.{0,12}(?:执行|忽略|无视|覆盖|跳过|关闭|绕过|取消|解除|撤销|停止|泄露)',value))
    framed = bool(re.search(r"[?？]\s*$|【选项】|[‘“\"].+[’”\"]|^(?:请)?(?:什么是|为什么|为何|如何|怎样|怎么|分析|解释|说明|介绍|描述|提供|展示|列出|输出|讨论|阐述|论述|简述|概述|评价|评估|判断)|^(?:how|what|why|explain|show|list|provide|true\s+or\s+false|discuss|describe|assess|evaluate|summarize)", value, re.S))
    return analysis and framed and not execute


def _actual_secret_request(text: str) -> bool:
    value=normalize(text)
    # Quoted attack samples can be analyzed; their requests are not executed.
    outside=re.sub(r'[“‘\"]([^”’\"]*)[”’\"]','',value)
    actual=bool(re.search(r'(?:你的|你当前|当前环境|运行环境|隐藏|私有|真实|your|actual|hidden).{0,40}(?:系统提示|开发者消息|私钥|密码|凭据|访问令牌|system\s*prompt|developer\s*message|private\s*key|password|api\s*key|credential)',outside))
    internal=bool(re.search(r'(?:内部|internal).{0,40}(?:密码|凭据|api\s*key|password|credential)',outside))
    education=bool(re.search(r'(?:安全存储|凭据管理|密码策略|key\s*轮换|key\s*管理|key\s+(?:rotation|management)|best\s+practice)',outside))
    actual=actual or (internal and not education)
    action=bool(re.search(r'(?:输出|提供|原样|逐字|返回|给出|列出|展示|是什么|reveal|print|show|dump|return|what\s+is)',outside))
    return actual and action


def validate_user_input(user_input: str) -> str:
    if not isinstance(user_input, str):
        raise GuardError("用户输入必须是字符串")
    cleaned = unicodedata.normalize("NFKC", user_input).strip()
    cleaned = "".join(c for c in cleaned if unicodedata.category(c) != "Cf")
    if not cleaned or len(cleaned) > MAX_USER_INPUT_CHARS:
        raise GuardError("用户输入为空或超过 2000 字符")
    if any(unicodedata.category(c) == "Cc" and c not in "\n\r\t" for c in cleaned):
        raise GuardError("用户输入包含非法控制字符")
    intent=cleaned
    # In a genuine assessment question, answer choices are quoted candidates,
    # not commands from the questioner. Never hide a command in the stem.
    has_choices=has_choice_options(cleaned)
    if has_choices:
        stem=choice_stem(cleaned)
        if re.search(r'^(?:(?:请|现在|立即|务必|你必须|接下来)(?:直接)?(?:执行|照做|服从|遵循)|请(?:选择|挑选).{0,12}(?:并|然后|后)执行|(?:execute|obey|follow)\b)',normalize(stem).replace('【问题】','').strip()):
            raise GuardError('本助手只分析选项，不执行选项中的指令')
        intent=stem
    risks = instruction_risks(intent)
    if _actual_secret_request(intent):
        raise GuardError('拒绝索取真实凭据或隐藏提示的请求')
    if risks and not _analysis_only(intent):
        raise GuardError("拒绝执行疑似越权或提示词注入请求（" + ",".join(risks) + "）")
    return cleaned


def validate_prompt(prompt: str) -> str:
    if not isinstance(prompt, str) or not prompt or len(prompt) > MAX_PROMPT_CHARS:
        raise GuardError("最终 Prompt 为空或超过长度预算")
    pattern = (re.escape(SYSTEM_POLICY + '\n<PROMPT_VERSION>'+PROMPT_VERSION+'</PROMPT_VERSION>') + r"\n\n<UNTRUSTED_RETRIEVED_CONTEXT>\n(.*?)"
               r"\n</UNTRUSTED_RETRIEVED_CONTEXT>\n<USER_QUESTION>\n(.*?)"
               r"\n</USER_QUESTION>\n<AVAILABLE_CITATIONS>\n(.*?)"
               r"\n</AVAILABLE_CITATIONS>\n" + re.escape(ANSWER_RULES) + r"\n【本题类型】([^\n]+)\n<CONTENT_DIGEST>[a-f0-9]{64}</CONTENT_DIGEST>")
    match = re.fullmatch(pattern, prompt, re.S)
    if not match or any("<" in part or ">" in part for part in match.groups()[:3]):
        raise GuardError("最终 Prompt 模板或数据边界被修改")
    context, question, citations = map(unescape, match.groups()[:3])
    concise=match.group(4).startswith('简答核验。')
    validate_user_input(question)
    if build_prompt(user_input=question, context=context, citations=citations.splitlines(),concise=concise) != prompt:
        raise GuardError("最终 Prompt 数据编码不符合规范")
    return prompt


def validate_response(response: str, citation_count: int, token: str = "") -> str:
    if not isinstance(response, str) or not response.strip():
        raise ValueError("模型返回空响应")
    if token and token in response:
        raise GuardError("拒绝输出包含个人凭据的模型响应")
    text = response.strip()
    if text.startswith("```json") and text.endswith("```"):
        text = text[7:-3].strip()
    try:
        obj = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ValueError("模型响应不是合法 JSON") from exc
    if not isinstance(obj, dict) or obj.get("decision") not in {"answer", "reject"}:
        raise ValueError("模型响应缺少合法 decision")
    if obj["decision"] == "reject":
        obj = {"decision": "reject", "answer": None, "evidence": [], "explanation": "拒绝执行越权请求。"}
    else:
        if not isinstance(obj.get("answer"), str) or not obj["answer"].strip():
            raise ValueError("正常回答缺少非空 answer")
        refs = obj.get("evidence", [])
        if not isinstance(refs, list) or any(type(n) is not int or not 1 <= n <= citation_count for n in refs):
            raise ValueError("模型引用了不存在的资料编号")
        obj = {"decision": "answer", "answer": obj["answer"], "evidence": list(dict.fromkeys(refs)),
               "explanation": str(obj.get("explanation", ""))[:2000]}
    return json.dumps(obj, ensure_ascii=False)
