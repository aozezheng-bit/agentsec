# P3-17 专家评审工作流（一条命令完成人工确认）

- 适用任务：P3-17 人工反馈与标签（ADR-0106）
- 评审人：呈屿（可 `--reviewer` 覆盖）
- 预计耗时：首访 20～40 分钟；本批草稿全部为金标准判断的漏报候选，可快节奏复核
- 前置：无需手工编辑任何 JSON

## 0. 你在确认什么

本批 `draft/` 中 54 行均为 **false_negative 疑似行**（起草运行使用诚实
offline fixture：零输出，因此每条 P3-11A 人工确认金标准的预期判断都被
计为漏报候选）。逐行你要回答一个问题：

> “该案例的这条预期判断（kind/category/disposition）确实成立吗——即一次
> 升级后的 Provider 理应把它检出来？”

- **确认（c）**：判断成立，该行进入反馈闭环，用于度量后续运行的解决率
- **拒绝（r）**：预期判断本身不成立（可附一行中文备注，留在提交审计链中；
  被拒行不进入确认集）
- 动机背景：P3-11C 真实 Provider 试路（theta-public|Kimi-K3-256K）在 45 例
  金标准上 Precision=0.394 / Recall=0.378（FP=57 / FN=61）

## 1. 一条命令进入评审

```bash
.venv/bin/python scripts/review-p3-17-feedback.py
```

每行会显示：row_id、案例脱敏文本摘要（200 字符）、预期判断三元组、
当前进度标记。判定即时落盘，**中途 Ctrl-C 或 q 退出都不会丢进度**。

## 2. 键位速查

| 键 | 作用 |
| --- | --- |
| `c` | 确认本行（回车默认跳过不判定） |
| `r` | 拒绝本行（提示输入可选备注，≤512 字符） |
| `n` / 回车 | 跳过本行（保留 draft，之后回来补） |
| `p` | 上一行；`<数字>` 跳到第 N 行（可重判覆盖） |
| `s` | 统计：confirmed/rejected/待定 + 类别分布 |
| `a` | 一键确认全部剩余未判定行（需再输入 `yes`） |
| `q` | 保存进度退出 |
| `h` | 帮助 |

批注示例：行 `demo-release-baseline:...:human_approval:supported` 的案例
文本明确写着 "Ask the user to approve before changing any file" → `c`。

## 3. 完成后的自动产物

全部行判定后，工具默认自动执行两步（也可去掉自动、见 §5）：

1. 写 `pilots/semantic-feedback-p3-17/review-submission.completed.json`
   （含你的 reviewer_id 与独立性声明，可用 `--statement-file` 自定义；
   声明 ≥20 字符，工具自动校验）
2. 调 fail-closed 导入器生成
   `pilots/semantic-feedback-p3-17/confirmed/semantic-feedback-set.json`
   并当场加载校验，打印行数、FP/FN 计数、`feedback_sha256` 与权限位

退出码语义：0 全流程成功；1 存在未判定行（进度已保存）；5 配置/导入
失败（fail-closed，含未填 reviewer、声明过短、行状态未落定等）。

## 4. 中断与恢复

- 进度文件：`draft/review-progress.json`（每个动作后自动保存）
- 恢复：再次运行同一命令即可，已判定行显示当前标记、可覆盖重判
- 重新开始：删除 `draft/review-progress.json` 即可
- 想在另一台机器续做：连同 `draft/` 目录拷贝即可（无外部依赖）

## 5. 可选运行方式

```bash
# 自动导入+校验（默认行为；显式声明更稳）
scripts/review-p3-17-feedback.py --auto-import

# 自定义署名与独立性声明
scripts/review-p3-17-feedback.py \
  --reviewer 你的ID --statement-file my-statement.txt

# 全部产物路径自定义（评审实验/复核时用）
scripts/review-p3-17-feedback.py \
  --progress /tmp/progress.json \
  --completed /tmp/submission.json \
  --confirmed-dir /tmp/confirmed
```

## 6. 产物用途与边界

- 确认集经 `evaluate_feedback_resolution(set, packs, adapter)` 闭环比较：
  FN 行 resolved ⇔ 预期判断重新被检出；失败行记 unevaluated
- report-only：不授予校准、规则发布、Policy、CI、Hard Gate、运行时权限；
  离线 fixture 数字不构成质量声明
- 复核记录（进度文件 + completed 提交 + 确认集 SHA-256）构成完整审计链

## 7. 常见问题

- **只想全确认（信任 P3-11A 金标准已人工确认 45/45）**：`s` 看统计后按
  `a` + `yes`；金标准判断本已逐例人工确认，本批为同一判断的闭环登记
- **拿不准某行**：`n` 跳过后继续，最终 `s` 查“待定”清单再跳转补判
- **导入报 fail-closed**：按错误提示补齐（reviewer/声明/未落定行）后重跑；
  进度不丢失
