"""Render fixed comparisons and per-question regressions without model calls."""
from collections import Counter
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
RESULTS=ROOT/'experiments/v28_1/results'
KEYS=['A','H','H1','H2','H3']
LABELS={'A':'v17 基线（当前护栏、不追加来源）','H':'原 f2868e6 生产逻辑',
        'H1':'仅修复候选保留','H2':'仅恢复答案完整性','H3':'两项同时修复'}


def read(name):return json.loads((RESULTS/name).read_text(encoding='utf-8'))
def pct(value):return 'N/A' if value is None else f'{value:.2%}'
def details(key,split):return {r['question_id']:r for r in [json.loads(l) for l in (RESULTS/f'{key}_{split}_details.jsonl').read_text(encoding='utf-8').splitlines()]}


def main():
    selection=read('selection.json');release=read('release_decision.json');tests=read('tests.json');safety=read('safety_audit.json')
    av=read('A_validation_summary.json');cv=read('H3_validation_summary.json')
    ah=read('A_holdout_summary.json');ch=read('H3_holdout_summary.json')
    lines=['# V28.1：准确率回退修复与基线发布门槛', '',
           '起点：`f2868e6`。本轮实际运行 A/H/H1/H2/H3 的固定验证集及保留集，对所有输出使用同一严格评分器。没有上传课堂平台，也没有新增运行时题目特判或修改知识源。', '',
           f"**最终默认：{release['default_variant']}。新候选允许提交平台：{'是（仅表示评测门槛通过，本轮未上传）' if release['new_candidate_release_allowed'] else '否'}。** 验证集预选 {selection['selected_variant']}；保留集只确认或否决，没有重新选型。", '',
           f"H3 最终语义正确率：验证集 {pct(cv['final_semantic_accuracy'])}（A：{pct(av['final_semantic_accuracy'])}），保留集 {pct(ch['final_semantic_accuracy'])}（A：{pct(ah['final_semantic_accuracy'])}）。但验证集首要控制为 {pct(cv['target_control_accuracy'])}，A 为 {pct(av['target_control_accuracy'])}，因此本轮只能说最终语义已恢复到基线水平，不能说综合发布门槛已经通过。", '',
           '## 修复内容', '',
           '1. 候选生成和使用分开。候选保留开启时，独立检索的实际融合结果进入最终决策；最多三份候选指南预留上下文位置，ID 传入 evidence isolation。指南只有在实际正文匹配注册来源、引文及 schema 检查通过后才能成为证据，不能只凭 metadata 获得事实权威。',
           '2. 充分回答模式要求主控制、直接原因、相关核心机制及必要验证，不再给简答设置过短的固定字数上限。只有来源控制冲突，或短答案对多条已验证来源机制覆盖明显不足时，触发一次条件复核；充分草稿不重复复核。没有追加整段指南或关键词填充。词汇覆盖只作复核触发信号，不作正确性判据，仍可能漏报或误触发。',
           '3. A 纳入候选。先看最终语义正确率，再看首要控制；最终正确率、首要控制和 recall@3 均不得低于 A。安全召回100%、正常误拒0、推理错误0也是门槛。完全同分保留 A；保留集只能否决已选新方案。',
           '4. 默认入口已支持真实 A 路径：保留 v17 的检索、生成和独立复核，使用当前护栏和外部凭据；取消 v17 最后追加的来源段落。旧严格评分本来就剥离这些段落，因此它们不再掩盖 synthesis。A 的运行时代码位于 `baseline_v17/`，不依赖实验目录或开发标签。', '',
           '## 同条件真实模型对照', '',
           '沿用 v28 的固定 split：每个评估子集27题（9选择、18简答）。相同知识源快照、模型服务、温度0、输出预算1000 tokens、top_k=5、上下文5份/6000字符、个人库关闭、并发4。使用本轮新缓存，各版本完全相同请求共享响应；没有复用旧轮生成结果。H 从原提交固定，H1 不改生成策略，H2 不改候选保留策略。本轮 H 是旧代码的新一轮响应及评分，不必与旧报告逐字或逐分相同；跨轮服务输出及自动评分并非完全确定。A 使用自己的 v17 检索与复核行为，候选链的开关不作用于 A。', '']
    paired={};matrices={};survival_audit={}
    for split in ['validation','holdout']:
        summaries={key:read(f'{key}_{split}_summary.json') for key in KEYS}
        data={key:details(key,split) for key in KEYS}
        for key in ['H1','H3']:
            checked=[r for r in data[key].values() if r.get('fusion',{}).get('reserved_candidates')]
            losses=[]
            for r in checked:
                reserved=set(r['fusion']['reserved_candidates'])
                for stage,field in [('fusion','sources'),('prepared','sources'),('evidence','retained_sources')]:
                    missing=reserved-set(r.get(stage,{}).get(field,[]))
                    if missing:losses.append({'question_id':r['question_id'],'stage':stage,'missing':sorted(missing)})
            survival_audit[f'{key}_{split}']={'reserved_cases':len(checked),'losses':losses}
        lines += [f'### {split}', '',
                  '| 版本 | target-control | recall@3 | evidence survival | final semantic | 选择题 | 简答题 | attack recall（输入护栏） | benign false-reject（模型） |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
        for key,row in summaries.items():
            lines.append('| '+key+' '+LABELS[key]+' | '+' | '.join(pct(v) for v in [row['target_control_accuracy'],row['candidate_recall']['3'],row['evidence_survival'],row['final_semantic_accuracy'],row['choice_accuracy'],row['short_answer_accuracy'],row['attack_recall'],row['benign_false_reject_rate']])+' |')
        lines += ['', 'evidence survival 的分母为候选目录检索到正确规范控制的题数；全体样本的阶段存活另列。只按注册 source ID 统计，语义等价但没有该 ID 的外部材料不会被算作该指南。', '',
                  f"实际预留指南核查：H1 / H3 各有 {survival_audit['H1_'+split]['reserved_cases']} / {survival_audit['H3_'+split]['reserved_cases']} 条普通场景进入保留策略，经过 fusion、prepare、evidence 的预留指南丢失分别为 {len(survival_audit['H1_'+split]['losses'])} / {len(survival_audit['H3_'+split]['losses'])}。这不保证正确控制一定进入Top3；未进入Top3仍是候选召回瓶颈。", '',
                  '| 版本 | 来源存活 retrieval → fusion → prepare → evidence（全体分母） | 失败阶段计数 | 推理错误 | 评分错误 | 条件复核次数 |',
                  '|---|---|---|---:|---:|---:|']
        for key,row in summaries.items():
            records=list(data[key].values())
            survival=[sum(r['evaluation']['source_survival'][stage] for r in records)/len(records) for stage in ['retrieval','fusion','prepared','evidence']]
            reviews=(str(sum(bool(r['generation'].get('correction_attempted')) for r in records))+'（失败'+str(sum(bool(r['generation'].get('review_error')) for r in records))+'）') if key!='A' else '基线常规独立复核'
            lines.append(f"| {key} | {' → '.join(map(pct,survival))} | `{json.dumps(row['failure_stages'],ensure_ascii=False)}` | {row['error_count']} | {row['scoring_error_count']} | {reviews} |")
            matrix=Counter((r['evaluation']['expected_control'],r['evaluation']['predicted_control'] or 'unresolved') for r in records)
            matrices[f'{key}_{split}']=[{'desired':a,'predicted':b,'count':n} for (a,b),n in sorted(matrix.items())]
        lines += ['', '| 版本 | 相比 H 修复 / 引入回归（最终语义） | 相比 A 修复 / 引入回归（最终语义） |', '|---|---:|---:|']
        for key in KEYS:
            counts=[]
            for base in ['H','A']:
                repaired=sum(not data[base][i]['evaluation']['final_semantic_correct'] and data[key][i]['evaluation']['final_semantic_correct'] for i in data[key])
                regressed=sum(data[base][i]['evaluation']['final_semantic_correct'] and not data[key][i]['evaluation']['final_semantic_correct'] for i in data[key])
                counts.append(f'{repaired} / {regressed}')
            lines.append(f"| {key} | {' | '.join(counts)} |")
        lines += ['', '逐题对照（✓=严格语义通过，×后列首个观察到的失败阶段；评分错误独立标记）：', '',
                  '| question_id | 正确控制 | A | H | H1 | H2 | H3 |', '|---|---|---|---|---|---|---|']
        split_pairs=[]
        for identifier in sorted(data['A']):
            record={'question_id':identifier,'question_type':data['A'][identifier]['question_type'],
                    'expected_control':data['A'][identifier]['evaluation']['expected_control'],'versions':{}}
            cells=[]
            for key in KEYS:
                r=data[key][identifier];e=r['evaluation']
                record['versions'][key]={'primary_correct':e['target_control_correct'],'semantic_correct':e['final_semantic_correct'],
                    'mechanism_coverage':e['mechanism_coverage'],'failure_stage':e['failure_stage'],'source_survival':e['source_survival'],
                    'bounded_candidate_present':e['expected_control'] in r.get('router',{}).get('candidate_controls',[]),
                    'reserved_candidates':r.get('fusion',{}).get('reserved_candidates',[]),
                    'review_attempted':r['generation'].get('correction_attempted'), 'scoring_error':e.get('scoring_error'),
                    'vs_H':'repaired' if e['final_semantic_correct'] and not data['H'][identifier]['evaluation']['final_semantic_correct'] else 'regressed' if not e['final_semantic_correct'] and data['H'][identifier]['evaluation']['final_semantic_correct'] else 'unchanged',
                    'vs_A':'repaired' if e['final_semantic_correct'] and not data['A'][identifier]['evaluation']['final_semantic_correct'] else 'regressed' if not e['final_semantic_correct'] and data['A'][identifier]['evaluation']['final_semantic_correct'] else 'unchanged'}
                cells.append('✓' if e['final_semantic_correct'] else '× '+e['failure_stage'])
            lines.append(f"| {identifier} | {record['expected_control']} | {' | '.join(cells)} |")
            split_pairs.append(record)
        paired[split]=split_pairs
        lines += ['', '完整答案、引文核验、机制判定和各阶段来源见对应 `*_details.jsonl`；逐题修复/回归的结构化字段见 `paired_comparison.json`。', '']
    lines += ['## 诊断及评分解释', '',
              '`retrieval_miss`：目录与实际融合均未找到正确来源；`fusion_loss`：候选存在但融合丢失；`context_loss`：融合存在但 prepare 裁剪丢失；`evidence_extraction_miss`：已进入上下文但证据抽取未保留；`generation_wrong_primary` / `generation_incomplete`：来源存活但首要控制错误/机制不全。只有实际执行了有效 reranker 且将候选排除才可记 `rerank_miss`。`evaluation_error` 不冒充生成错误。阶段是定位线索，不是因果归因。', '',
              '候选召回按筛选前的控制目录排序计数，实际有界Top3另见 `router.candidate_controls`。目录到fusion的丢失也可能包括Top3预算筛选，不能全部归因RRF权重；逐题文件另存 `bounded_candidate_present` 及预留ID，真实预留存活核查见 `candidate_survival_audit.json`。', '',
              '评分先判主要控制、再看机制；选择题严格核对字母。盲控制分类只看实际 synthesis 和来源目录，不看标准答案；机制评分仅在推理完成后使用参考答案。评分必须给出实际答案的精确引用，覆盖至少80%的核心参考要求才能通过。JSON/引文校验失败保守计错且单列，没有挑选有利重评分。', '',
              '评分与被测模型来自同一服务，不等同独立专家标注。全部数据曾用于历史开发，holdout 只作固定回归最终确认，不能证明隐藏分布不回退；27题的小样本尤其不能保证平台成绩。', '',
              '## 测试、安全与发布决定', '',
              f"{tests['tests_run']} 项测试通过，failures={tests['failures']}，errors={tests['errors']}。含原安全测试、10组边界40个子用例、九类机制完整性、候选生存、完整答案不重复复核、A默认分派、基线复核保留，以及选型/诊断门槛。模拟模型测试不代替上述真实模型评测。", '',
              f"输入护栏未修改：TP={safety['tp']}，TN={safety['tn']}，FP={safety['fp']}，FN={safety['fn']}。正常输入误拒率0%；模型正常题误拒另列于表。外部凭据管理继续保留，ZIP与待提交源码均不得含真实Token或评测标签。", '',
              '最终发布判断：', '', '```json',json.dumps(release,ensure_ascii=False,indent=2),'```', '',
              '本轮平台上传次数：**0**。历史 V28 的77.027%不是本轮成绩。若门槛未通过，默认保留 A，禁止用本轮新候选上传；即使回归门槛通过，也只表示达到下一次平台验证的技术门槛，不等于已经提高平台成绩。', '',
              '## 复现入口', '', '```powershell','python tools/verify_v28_1.py',
              'python experiments/v28_1/run_experiments.py',
              'python experiments/v28_1/score_experiments.py',
              'python experiments/v28_1/finalize.py select',
              'python experiments/v28_1/run_experiments.py --split holdout',
              'python experiments/v28_1/score_experiments.py --split holdout',
              'python experiments/v28_1/finalize.py release',
              'python tools/render_v28_1_reports.py','```', '',
              '已有结果和冻结选择拒绝覆盖。新一轮复现应使用独立结果目录副本，不能删除当前记录后据错题调参。来源、代码、split和评分器指纹随 JSON 保存；请求与评分缓存留本地，不上传仓库。']
    (ROOT/'V28_1_RESULTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    (RESULTS/'paired_comparison.json').write_text(json.dumps(paired,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (RESULTS/'confusion_matrices.json').write_text(json.dumps(matrices,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (RESULTS/'candidate_survival_audit.json').write_text(json.dumps(survival_audit,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Rendered V28.1 results and per-question repair/regression comparisons.')


if __name__=='__main__':main()
