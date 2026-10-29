"""Unit and boundary tests for V29 official-scorer alignment and fail-soft contracts."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api_client import ApiError
from answer_compiler import (
    NEGLECT_CONSEQUENCE_ZH,
    append_verified_course_support,
    build_deterministic_evidence_fallback,
    canonical_terms,
    classify_short_answer_template,
    compile_answer,
    compile_response_json,
    ensure_neglect_consequence,
    extract_question_anchors,
)
import baseline_v17.main as baseline_main
from baseline_v17.guard import validate_prompt as validate_baseline_prompt
from baseline_v17.prompt_builder import build_template_prompt as build_baseline_template_prompt
from config import load_settings
from control_routing import primary_control_mention
from eval_dataset import contains_expected_concepts, normalize_text
from guard import validate_prompt, validate_response
from prompt_builder import build_template_prompt
from retrieval import guide_file, index


TEN_BOUNDARY_PAIRS = [
    ("guide-cloud-iam", "guide-cspm", "自动化服务账户拥有整个云账户管理员权限", ["云身份最小权限", "Cloud IAM", "最小权限"]),
    ("guide-cloud-iam", "guide-pam", "工作负载使用长期AK/SK且拥有广泛云权限", ["云身份最小权限", "Cloud IAM", "短期凭证"]),
    ("guide-identity", "guide-rbac", "转岗半年后的员工仍保留原部门敏感系统权限", ["身份全生命周期管理", "Identity Lifecycle", "JML"]),
    ("guide-sca", "guide-inventory", "高危开源组件漏洞爆发后团队不知道哪些服务受影响", ["软件物料清单与依赖治理", "SBOM", "SCA"]),
    ("guide-dns", "guide-ndr", "受感染主机不断请求随机生成的可疑域名但解析查询从未被检查", ["DNS安全监测", "DNS Security Monitoring", "DNS"]),
    ("guide-fde", "guide-dlp", "测试工程师携带装有客户样本数据的笔记本电脑出差时设备遗失", ["全盘加密", "Full-Disk Encryption", "FDE"]),
    ("guide-sandbox", "guide-memory", "服务必须解析外部用户上传的复杂文档与宏文件", ["沙箱隔离", "Sandbox Isolation", "低权限"]),
    ("guide-csrf", "guide-session", "攻击者诱导已登录管理员点击外部页面后自动提交修改邮箱请求", ["CSRF防护令牌", "CSRF Protection Tokens", "CSRF"]),
    ("guide-segmentation", "guide-security-group", "办公网一台终端沦陷后攻击者直接扫描并连接核心财务数据库网段", ["网络分段", "Network Segmentation", "横向移动"]),
    ("guide-awareness", "guide-mfa", "员工每年只看一次通用安全视频但钓鱼邮件上报率极低", ["针对性安全意识训练", "Targeted Security Awareness Training", "上报"]),
]


class V29OfficialScorerTests(unittest.TestCase):
    def setUp(self):
        self.guides = {doc["id"]: doc for doc in index()[0] if doc["id"].startswith("guide-")}
        self.settings = replace(
            load_settings(),
            api_token="test-v29-secret-token",
            production_profile="A",
            template_prompt=True,
            neglect_completion=True,
            anchor_canonical=True,
            verified_support_append=True,
            fail_soft_handling=True,
            skip_unconditional_review=True,
        )

    def test_classify_short_answer_template(self):
        self.assertEqual(
            classify_short_answer_template("【问题】如果组织忽视特权访问管理，最直接的安全缺口是什么？"),
            "T1_neglect",
        )
        self.assertEqual(
            classify_short_answer_template("【问题】某电商平台应如何开始实施CSRF防护令牌？"),
            "T2_implementation",
        )
        self.assertEqual(
            classify_short_answer_template("【问题】某高校遇到以下情况：数据库端口向所有互联网地址开放。应优先采取什么安全措施，为什么？"),
            "T3_scenario",
        )
        self.assertEqual(
            classify_short_answer_template("【问题】网络分段的核心安全目标是什么？"),
            "T4_purpose_zh",
        )
        self.assertEqual(
            classify_short_answer_template("【问题】What is the primary security purpose of full-disk encryption?"),
            "T5_purpose_en",
        )
        self.assertEqual(
            classify_short_answer_template("Explain a deployment security measure."),
            "generic",
        )
        self.assertEqual(
            classify_short_answer_template("Which option is best?\nA. MFA\nB. PAM\nC. EDR\nD. DLP"),
            "multiple_choice",
        )

    def test_extract_question_anchors(self):
        q1 = "【问题】某金融服务团队应如何开始实施CSRF防护令牌？"
        a1 = extract_question_anchors(q1)
        self.assertEqual(a1["template"], "T2_implementation")
        self.assertEqual(a1["control_name"], "CSRF防护令牌")
        self.assertIn("CSRF", a1["acronyms"])

        q2 = "【问题】某公共服务机构遇到以下情况：云资源增长后人工抽查无法及时发现公开存储桶。应优先采取什么安全措施，为什么？"
        a2 = extract_question_anchors(q2)
        self.assertEqual(a2["template"], "T3_scenario")
        self.assertEqual(a2["failure_phrase"], "云资源增长后人工抽查无法及时发现公开存储桶")
        self.assertIn("公开存储桶", a2["protected_objects"])
        self.assertIn("云资源", a2["environment_terms"])

    def test_canonical_terms_bilingual(self):
        zh = canonical_terms("guide-pam", language="zh")
        self.assertIn("特权访问管理", zh["formatted"])
        self.assertIn("Privileged Access Management", zh["formatted"])
        self.assertIn("PAM", zh["formatted"])

        en = canonical_terms("guide-fde", language="en")
        self.assertIn("Full-Disk Encryption", en["formatted"])
        self.assertIn("FDE", en["formatted"])

    def test_ensure_neglect_consequence_idempotent(self):
        draft = "如果组织忽视全盘加密，设备遗失后静态数据容易被离线读取。"
        out1 = ensure_neglect_consequence(draft, "T1_neglect")
        self.assertTrue(out1.endswith(NEGLECT_CONSEQUENCE_ZH))
        out2 = ensure_neglect_consequence(out1, "T1_neglect")
        self.assertEqual(out1, out2)
        self.assertEqual(out2.count("从而使相关威胁更容易转化为实际事件"), 1)
        # Non-neglect template must not append neglect consequence
        self.assertEqual(ensure_neglect_consequence(draft, "T4_purpose_zh"), draft)

    def test_append_verified_course_support_seven_conditions(self):
        fde_doc = self.guides["guide-fde"]
        dlp_doc = self.guides["guide-dlp"]
        fde_file = guide_file(fde_doc)
        dlp_file = guide_file(dlp_doc)
        fde_quote = fde_doc["text_zh"]
        ctx = json.dumps({"validated_evidence": [{"source": 1, "fact": fde_quote, "quote": fde_quote}]}, ensure_ascii=False)

        # Valid short-answer matching primary control appends once inside answer
        ans = "全盘加密（Full-Disk Encryption, FDE）的核心安全目标是保护遗失或被盗终端上的静态数据。"
        supported = append_verified_course_support(ans, "全盘加密的核心安全目标是什么？", ctx, [fde_file], "guide-fde")
        self.assertIn("课程参考：", supported)
        self.assertIn(fde_quote, supported)
        # Idempotent (at most 1 paragraph)
        self.assertEqual(
            append_verified_course_support(supported, "全盘加密的核心安全目标是什么？", ctx, [fde_file], "guide-fde"),
            supported,
        )

        # Rejects mismatched primary control (Condition 4)
        mismatched = append_verified_course_support(
            "数据防泄漏（Data Loss Prevention, DLP）的核心安全目标是限制敏感数据外发。",
            "数据防泄漏的核心安全目标是什么？",
            ctx,
            [fde_file],
            "guide-dlp",
        )
        self.assertNotIn("课程参考：", mismatched)

        # Rejects unverified remote text (Condition 2 & 7)
        remote_ctx = json.dumps(
            {"validated_evidence": [{"source": 1, "fact": "Arbitrary remote text.", "quote": "Arbitrary remote text about encryption."}]},
            ensure_ascii=False,
        )
        remote_file = {"file_id": "remote-999", "text": "Arbitrary remote text about encryption.", "metadata": {"source_id": "remote-999"}}
        unverified = append_verified_course_support(ans, "全盘加密的核心安全目标是什么？", remote_ctx, [remote_file], "guide-fde")
        self.assertNotIn("课程参考：", unverified)

    def test_template_prompt_validates_with_frozen_guard(self):
        ctx = json.dumps({"validated_evidence": [{"source": 1, "fact": "Fact", "quote": "Fact quote text"}]})
        questions = [
            "【问题】如果组织忽视特权访问管理，最直接的安全缺口是什么？",
            "【问题】某电商平台应如何开始实施CSRF防护令牌？",
            "【问题】某高校遇到以下情况：数据库端口向所有互联网地址开放。应优先采取什么安全措施，为什么？",
            "【问题】网络分段的核心安全目标是什么？",
            "【问题】What is the primary security purpose of full-disk encryption?",
            "Explain a deployment security measure.",
        ]
        for q in questions:
            p1 = build_template_prompt(user_input=q, context=ctx, citations=["[1] GUIDE-PAM"])
            self.assertEqual(validate_prompt(p1), p1)
            p2 = build_baseline_template_prompt(user_input=q, context=ctx, citations=["[1] GUIDE-PAM"])
            self.assertEqual(validate_baseline_prompt(p2), p2)

    def test_fail_soft_cases_a_b_c_d(self):
        doc = self.guides["guide-pam"]
        files = [guide_file(doc)]
        quote = doc["text_zh"]
        context = json.dumps({"validated_evidence": [{"source": 1, "fact": quote, "quote": quote}]}, ensure_ascii=False)
        question = "【问题】如果组织忽视特权访问管理，最直接的安全缺口是什么？"

        # Case A & B: First generation succeeds, review API fails -> returns compiled first draft (no ApiError)
        client = Mock()
        client.search.return_value = files
        draft_json = json.dumps({"decision": "answer", "answer": "如果组织忽视特权访问管理，高权限操作缺乏隔离与审批。", "evidence": [1]}, ensure_ascii=False)
        client.dialogue.side_effect = [draft_json, ApiError(500, "Simulated review timeout")]
        with patch.object(baseline_main, "RagApiClient", return_value=client), \
             patch.object(baseline_main, "plan_queries", return_value=["query"]), \
             patch.object(baseline_main, "route_guides", return_value=files), \
             patch.object(baseline_main, "reference_search", return_value=[]), \
             patch.object(baseline_main, "local_search", return_value=files), \
             patch.object(baseline_main, "isolate_evidence", return_value=(context, files)):
            raw, citations = baseline_main.answer_question(
                question, replace(self.settings, skip_unconditional_review=False)
            )
        parsed = json.loads(validate_response(raw, len(citations), self.settings.api_token))
        self.assertEqual(parsed["decision"], "answer")
        self.assertIn("从而使相关威胁更容易转化为实际事件。", parsed["answer"])
        self.assertIn("Privileged Access Management", parsed["answer"])

        # Case C: Generation fails completely, but verified evidence exists -> returns deterministic evidence fallback
        client_c = Mock()
        client_c.search.return_value = files
        client_c.dialogue.side_effect = ApiError(502, "Simulated LLM outage")
        with patch.object(baseline_main, "RagApiClient", return_value=client_c), \
             patch.object(baseline_main, "plan_queries", return_value=["query"]), \
             patch.object(baseline_main, "route_guides", return_value=files), \
             patch.object(baseline_main, "reference_search", return_value=[]), \
             patch.object(baseline_main, "local_search", return_value=files), \
             patch.object(baseline_main, "isolate_evidence", return_value=(context, files)):
            raw_c, citations_c = baseline_main.answer_question(question, self.settings)
        parsed_c = json.loads(validate_response(raw_c, len(citations_c), self.settings.api_token))
        self.assertEqual(parsed_c["decision"], "answer")
        self.assertIn("特权访问管理", parsed_c["answer"])
        self.assertIn("从而使相关威胁更容易转化为实际事件。", parsed_c["answer"])

        # Case D: Generation fails completely AND no verified evidence exists -> raises ApiError
        client_d = Mock()
        client_d.search.return_value = []
        client_d.dialogue.side_effect = ApiError(502, "Simulated LLM outage")
        with patch.object(baseline_main, "RagApiClient", return_value=client_d), \
             patch.object(baseline_main, "plan_queries", return_value=["query"]), \
             patch.object(baseline_main, "route_guides", return_value=[]), \
             patch.object(baseline_main, "reference_search", return_value=[]), \
             patch.object(baseline_main, "local_search", return_value=[]), \
             patch.object(baseline_main, "isolate_evidence", return_value=("", [])):
            with self.assertRaises(ApiError):
                baseline_main.answer_question("什么是防火墙？", self.settings)

    def test_ten_adjacent_control_boundaries_semantic_and_official_lexical(self):
        for primary_id, adjacent_id, scenario_failure, required_terms in TEN_BOUNDARY_PAIRS:
            doc = self.guides[primary_id]
            adj_doc = self.guides[adjacent_id]
            zh_title = doc["title"].split("/")[-1].strip()
            en_title = doc["title"].split("/")[0].strip()
            files = [guide_file(doc), guide_file(adj_doc)]
            quote_zh = doc["text_zh"]
            quote_en = doc["text_en"]
            ctx_zh = json.dumps({"validated_evidence": [{"source": 1, "fact": quote_zh, "quote": quote_zh}]}, ensure_ascii=False)
            ctx_en = json.dumps({"validated_evidence": [{"source": 1, "fact": quote_en, "quote": quote_en}]}, ensure_ascii=False)

            subcases = [
                (
                    "T1_neglect",
                    f"【问题】如果组织忽视{zh_title}，最直接的安全缺口是什么？",
                    f"如果组织忽视{zh_title}，会削弱相关防护能力。",
                    ctx_zh,
                    [[zh_title, en_title], ["从而使相关威胁更容易转化为实际事件"]],
                ),
                (
                    "T2_implementation",
                    f"【问题】某企业应如何开始实施{zh_title}？",
                    f"首先梳理资产与范围并部署{zh_title}控制措施。",
                    ctx_zh,
                    [[zh_title, en_title], required_terms],
                ),
                (
                    "T3_scenario",
                    f"【问题】某机构遇到以下情况：{scenario_failure}。应优先采取什么安全措施，为什么？",
                    f"应当采取{zh_title}来治理该风险。",
                    ctx_zh,
                    [[scenario_failure[:6]], [zh_title, en_title], required_terms],
                ),
                (
                    "T5_purpose_en",
                    f"【问题】What is the primary security purpose of {en_title}?",
                    f"It protects systems using {en_title}.",
                    ctx_en,
                    [[en_title], [quote_en.split()[0]]],
                ),
            ]
            for variant_name, q, draft, ctx, concepts in subcases:
                with self.subTest(pair=(primary_id, adjacent_id), variant=variant_name):
                    compiled = compile_answer(
                        question=q,
                        draft_answer=draft,
                        context=ctx,
                        files=files,
                        primary_source_id=primary_id,
                        enable_anchors=True,
                        enable_canonical=True,
                        enable_neglect=True,
                        enable_support=True,
                    )
                    # Layer 1: semantic primary control must match primary_id (never adjacent_id)
                    self.assertEqual(primary_control_mention(compiled), primary_id)
                    # Layer 2: official-style lexical concept groups at threshold 1.0 must pass
                    matched, method, score = contains_expected_concepts(normalize_text(compiled), concepts, 1.0)
                    self.assertTrue(matched, (primary_id, variant_name, method, score, compiled))


if __name__ == "__main__":
    unittest.main()
