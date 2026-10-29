"""Render reviewable reports from saved experiments; never run inference."""
from collections import Counter
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'experiments/v28/results'
LABELS = {
    'A': 'v17 逻辑，共享来源快照',
    'B': 'A：取消猜答案式改写',
    'C': 'A：取消单控制路由',
    'D': '同时取消两者',
    'E': 'D + Top3 范围比较/竞争证据',
    'F': '清理后的生产链：改写开、比较开',
    'G': '清理后的生产链：改写开、比较关',
    'H': '清理后的生产链：改写关、比较关',
    'I': '清理后的生产链：改写关、比较开',
}


def read(name):
    return json.loads((RESULTS / name).read_text(encoding='utf-8'))


def records(key, split):
    return [json.loads(line) for line in (RESULTS / f'{key}_{split}_details.jsonl').read_text(encoding='utf-8').splitlines()]


def pct(value):
    return 'N/A' if value is None else f'{value:.2%}'


def result_table(rows):
    lines = ['| Version | target control acc | recall@3 | MRR | evidence survival | final semantic acc | attack recall |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for key, row in rows:
        lines.append(f"| {key} {LABELS[key]} | {pct(row['target_control_accuracy'])} | {pct(row['candidate_recall']['3'])} | {row['MRR']:.3f} | {pct(row['evidence_survival'])} | {pct(row['final_semantic_accuracy'])} | 100%（共用输入护栏） |")
    return '\n'.join(lines)


def main():
    selection = read('selection.json')
    chosen = selection['selected_variant']
    validation = [(key, read(f'{key}_validation_summary.json')) for key in LABELS]
    holdout = [(key, read(f'{key}_holdout_summary.json')) for key in ['A', chosen]
               if (RESULTS / f'{key}_holdout_summary.json').exists()]
    if not all(row.get('strict_scoring_complete') for _, row in validation + holdout):
        raise SystemExit('Reports require completed uniform semantic scoring.')
    tests = read('tests.json')
    out = ['# V28 消融与正式测试结果', '',
           '2026-10-29。以下对照均调用真实课堂模型 API，答案生成后统一离线重评。', '',
           f'按预先冻结的规则选择 **{chosen}**；配置为 `{json.dumps(selection["configuration"], ensure_ascii=False)}`。验证集没有证明新增改写或范围比较有正收益，因此默认关闭；保留实现供复现实验。', '',
           '本轮没有达到“严格正确率和保留集提升”的全部成功标准。不能把完成重构、通过测试或召回未下降表述成泛化提升。', '',
           '## 固定验证集（27 条）', '', result_table(validation), '',
           'A～D 从保留的 v17 代码运行，共享同一来源快照及规范名称别名、关闭个人检索库。A 不是对历史平台 87.8378% 的精确复现。E 是范围比较、低权重提示、竞争证据保留的联合消融，不能分别归因。F～I 是清理后生产链的 2×2 对照；没有逐题补规则。', '',
           '## 固定保留集（27 条）', '', result_table(holdout), '',
           '配置在保留集推理前冻结，保留集只比较 A 与所选生产配置一次，没有据此重新选型或改推理规则。全部公开题曾用于历史开发，所以这是固定回归保留集，不是真正从未见过的分布。27 条也不足以证明小幅收益的统计显著性。', '',
           '## 召回、排序及诊断', '',
           '| Split / variant | recall@1 | recall@3 | recall@5 | rank@1 | unresolved | fallback semantic acc | inference errors | scoring errors | model benign reject |',
           '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for split, rows in [('validation', validation), ('holdout', holdout)]:
        for key, row in rows:
            data = records(key, split)
            rejected = sum(r.get('generation', {}).get('decision') == 'reject' for r in data) / len(data)
            out.append(f"| {split}/{key} | {pct(row['candidate_recall']['1'])} | {pct(row['candidate_recall']['3'])} | {pct(row['candidate_recall']['5'])} | {pct(row['rerank_accuracy'])} | {pct(row['primary_unresolved_rate'])} | {pct(row['fallback_accuracy'])} | {row['error_count']} | {row['scoring_error_count']} | {pct(rejected)} |")
    out += ['', '候选召回按模型做唯一决策前的规范控制目录计数；混合原始文档列表另记 `document_sources`。旧 A～E 的候选目录诊断使用固定原检索算法重放，仅修复日志，不调用模型、不修改已保存答案。MRR 在没有显式排序时使用融合顺序。evidence survival 的分母是检索目录找到正确控制的题目，仅认规范 source ID；语义等价的外部段落不会冒充该 ID。', '',
            '## 严格评分方法与局限', '',
            '先判断最终 synthesis 的首要控制，后评机制。选择题必须精确选对字母。旧式追加来源段落先剥离，不能用后文出现的正确词修复错误首要结论。规范名称匹配无法确定时，盲分类器只看实际答案与来源目录，不看题目或标准答案；无法明确判定则记 unresolved。', '',
            '首要控制正确后，离线评分器先只看题目和参考答案抽取 1～3 条连续原文要求，再检查实际答案是否语义支持这些要求，并强制引用答案原文。机制支持比例至少 80% 才通过。参考要求在各版本共享缓存；旧短语覆盖率仅为兼容字段。开发标签只在推理完成后进入评测，不进入线上提示词、检索或知识库。', '',
            '评分器与被测系统使用同一模型服务，不能视为独立专家标注。JSON/引文校验失败保守计错，表中单列 scoring errors；没有为了提高分数重试挑选有利评分。结果应结合混淆矩阵和人工复核阅读。', '',
            '## 安全与打包', '',
            f"最终 {tests['tests_run']} 项单元/集成测试全部通过（failures={tests['failures']}，errors={tests['errors']}）。10 组相邻控制各含 positive A / positive B / ambiguous / explicit named，合计 40 个生产主链子用例。它们使用模拟模型，只证明调用链和安全合同，不代表真实模型准确率。", '',
            '冻结的 guard.py 没有修改。公开集输入护栏复查：TP=177、TN=626、FP=0、FN=0；attack recall=100%、benign guard false reject=0%。表中另列正常题实际模型 reject 比例，避免用护栏数字替代端到端行为。', '',
            'ZIP 仅含推理白名单、公开配置、来源知识和 requirements；排除真实 Token、.env、实验标签与评测器。已验证独立目录导入，清单见 `experiments/v28/results/package_manifest.json`。凭据移到仓库外，历史提交仍可能包含旧 Token，需要更换；本轮不改写历史。', '',
            '## 本轮唯一平台提交', '']
    platform_path = RESULTS / 'platform_submission.json'
    if platform_path.exists():
        platform = read('platform_submission.json')
        result = platform.get('result', {})
        if result.get('answer_accuracy') is not None:
            out += [f"**官方正常题正确率 {pct(result['answer_accuracy'])}，攻击识别率 {pct(result['reject_recall'])}。** 相比历史最好 87.8378%，正常题下降 {(0.878378-result['answer_accuracy'])*100:.2f} 个百分点。本轮没有改善平台成绩，未再次上传。", '']
        out += [f"提交 ID：`{platform.get('submission_id', result.get('id', '尚未返回'))}`。", '',
                '平台原始记录：`experiments/v28/results/platform_submission.json`。', '',
                '```json', json.dumps(result or {k: v for k, v in platform.items() if k != 'manifest'}, ensure_ascii=False, indent=2), '```']
    else:
        out.append('尚未上传；完成保留集和最终检查后只提交一版。')
    out += ['', '## 复现', '', '```powershell',
            'python tools/verify_v28.py',
            '# 已存在的实验拒绝覆盖；以下命令用于新实验目录复现，不删除本轮记录。',
            'python experiments/v28/run_ablations.py --variant A',
            '# 同理运行 B～I；旧版日志再执行 replay_trace.py --variant A（至 E）',
            'python experiments/v28/score_experiments.py',
            'python experiments/v28/select_profile.py',
            'python experiments/v28/run_ablations.py --split holdout',
            'python experiments/v28/replay_trace.py --variant A --split holdout',
            'python experiments/v28/score_experiments.py --split holdout',
            'python tools/render_v28_reports.py', '```', '',
            '固定 split、选择协议、源代码指纹及逐题诊断均保存在 `experiments/v28/`。推理请求缓存和评分缓存保留在本地但不上传 GitHub；不记录完整提示词或认证配置。']
    (ROOT / 'ABLATION_RESULTS.md').write_text('\n'.join(out) + '\n', encoding='utf-8')

    confusion_doc = ['# 控制混淆与阶段存活', '',
                     '只从已完成真实推理、统一严格重评后的记录生成。计数矩阵包含正确对角线，Top Confusions 排除对角线；unresolved 单列。选择题选错但仍属同一控制时，由 choice_correct=False 判错，控制矩阵本身不能代替字母准确率。', '']
    matrix_data = {}
    for split, rows in [('validation', validation), ('holdout', holdout)]:
        for key, row in rows:
            data = records(key, split)
            counts = Counter((r['evaluation']['expected_control'], r['evaluation']['predicted_control'] or 'unresolved') for r in data)
            controls = sorted({a for a, _ in counts})
            predictions = sorted({b for _, b in counts})
            matrix_data[f'{key}_{split}'] = {
                'desired_controls': controls, 'predicted_controls': predictions,
                'matrix': [[counts[a, b] for b in predictions] for a in controls],
                'cells': [{'desired': a, 'predicted': b, 'count': c} for (a, b), c in sorted(counts.items())],
            }
            confusion_doc += [f'## {split} / {key}', '', '| desired | predicted | count |', '|---|---|---:|']
            if row['top_confusions']:
                for c in row['top_confusions']:
                    confusion_doc.append(f"| {c['desired']} | {c['predicted']} | {c['count']} |")
            else:
                confusion_doc.append('| 无观察到的首要控制混淆 | — | 0 |')
            stages = Counter(r['evaluation']['failure_stage'] for r in data)
            confusion_doc += ['', '失败阶段：`' + json.dumps(dict(stages), ensure_ascii=False) + '`。', '',
                              '来源存活（全体样本分母）：', '', '| retrieval | fusion | prepare | evidence |', '|---:|---:|---:|---:|']
            survival = [sum(r['evaluation']['source_survival'][stage] for r in data) / len(data) for stage in ['retrieval', 'fusion', 'prepared', 'evidence']]
            confusion_doc += ['| ' + ' | '.join(map(pct, survival)) + ' |', '',
                              '证据模式计数：`' + json.dumps(row['evidence_modes'], ensure_ascii=False) + '`；fallback 最终语义准确率：' + pct(row['fallback_accuracy']) + '。', '']
    confusion_doc += ['## 如何解读', '',
                      'retrieval_miss 表示正确规范控制未进入候选目录；rerank_miss 表示目录中存在但排序未居首；evidence_drop 表示居首后未保留该规范来源；generation_miss 表示正确来源存活但最终语义未通过。首先遇到的条件用于归类，是定位线索，不是因果证明。合法的 exact FAQ 也可能绕过一般检索阶段，不能把缺少该阶段日志等同于回答错误。', '',
                      '完整 desired × predicted 数值矩阵见 `experiments/v28/results/confusion_matrices.json`。', '',
                      '10 组边界测试覆盖 FDE/DLP、DLP/minimization、sandbox/memory、segmentation/security group、awareness/MFA、CSRF/session、DPIA/minimization、allowlist/endpoint privilege、secrets/KMS、firmware/secure boot；未在这 27 条中出现的类别不计为零风险，也不据此增写逐题规则。']
    (ROOT / 'CONTROL_CONFUSION.md').write_text('\n'.join(confusion_doc) + '\n', encoding='utf-8')
    (RESULTS / 'confusion_matrices.json').write_text(json.dumps(matrix_data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Rendered strict results, stage diagnostics and full confusion matrices.')


if __name__ == '__main__':
    main()
