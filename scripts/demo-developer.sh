#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
output_dir=""
pause_enabled=true
show_rules=false
case_language="en"

usage() {
  cat <<'USAGE'
Usage: scripts/demo-developer.sh [OPTIONS]

Run the AgentSec Release Agent story as a presenter-friendly, step-by-step Demo.

Options:
  --no-pause          Run every step without waiting for Enter.
  --show-rules        Show the complete deterministic rule list during preflight.
  --case-language L   Demo Asset language: en or zh (default: en).
  --output-dir DIR    Preserve Demo artifacts in a new or empty directory.
  --python PATH       Use a specific Python 3.12 executable.
  -h, --help          Show this help message.

Environment:
  PYTHON              Default Python executable when --python is not supplied.
  NO_COLOR            Disable ANSI colors.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-pause)
      pause_enabled=false
      shift
      ;;
    --show-rules)
      show_rules=true
      shift
      ;;
    --case-language)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --case-language" >&2
        exit 2
      fi
      case_language="$2"
      shift 2
      ;;
    --output-dir)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --output-dir" >&2
        exit 2
      fi
      output_dir="$2"
      shift 2
      ;;
    --python)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --python" >&2
        exit 2
      fi
      python_executable="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$case_language" != "en" && "$case_language" != "zh" ]]; then
  echo "Unsupported Demo Asset language: $case_language (expected en or zh)" >&2
  exit 2
fi

if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  echo "Create .venv, set PYTHON, or pass --python PATH." >&2
  exit 2
fi

if [[ -z "$output_dir" ]]; then
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentsec-developer-demo.XXXXXX")"
elif [[ -d "$output_dir" ]]; then
  if [[ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "Output directory must be empty: $output_dir" >&2
    exit 2
  fi
else
  mkdir -p "$output_dir"
fi

if [[ ! -t 0 ]]; then
  pause_enabled=false
fi

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  bold=$'\033[1m'
  cyan=$'\033[36m'
  green=$'\033[32m'
  yellow=$'\033[33m'
  red=$'\033[31m'
  reset=$'\033[0m'
else
  bold=""
  cyan=""
  green=""
  yellow=""
  red=""
  reset=""
fi

agentsec=("$python_executable" -m agentsec)
if [[ "$case_language" == "zh" ]]; then
  demo_relative_root="demos/release-agent-zh"
else
  demo_relative_root="demos/release-agent"
fi
demo_root="$repository_root/$demo_relative_root"
baseline_root="$demo_root/baseline"
risky_root="$demo_root/risky-drift"
injection_root="$demo_root/prompt-injection"
malformed_root="$demo_root/malformed"
remediated_root="$demo_root/remediated"
baseline_path="$output_dir/live-baseline.json"

if [[ ! -d "$demo_root" ]]; then
  echo "Demo root not found: $demo_root" >&2
  exit 2
fi

heading() {
  local current="$1"
  local total="$2"
  local title="$3"
  printf '\n%s%s[%s/%s] %s%s\n' "$bold" "$cyan" "$current" "$total" "$title" "$reset"
  printf '%s\n' '--------------------------------------------------------------------------------'
}

note() {
  printf '%s%s%s\n' "$yellow" "$1" "$reset"
}

success() {
  printf '%s%s%s\n' "$green" "$1" "$reset"
}

fail() {
  printf '%s%s%s\n' "$red" "$1" "$reset" >&2
}

pause_for_next_step() {
  if [[ "$pause_enabled" == true ]]; then
    printf '\n%s按 Enter 继续下一步，Ctrl-C 可安全退出……%s' "$bold" "$reset"
    IFS= read -r _
  fi
}

show_command() {
  printf '\n%s$ %s%s\n' "$bold" "$1" "$reset"
}

run_json_command() {
  local destination="$1"
  local expected_exit="$2"
  local display_command="$3"
  shift 3

  show_command "$display_command"
  set +e
  "${agentsec[@]}" "$@" --format json > "$destination"
  local actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    fail "命令退出码不符合预期：期望 $expected_exit，实际 $actual_exit"
    exit 1
  fi
}

render_assessment() {
  local report_path="$1"
  local detail_mode="$2"

  "$python_executable" - "$report_path" "$detail_mode" <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
detail_mode = sys.argv[2]
payload = json.loads(report_path.read_text(encoding="utf-8"))
summary = payload["summary"]
policy = payload["policy"]
coverage = payload["assessment"]["coverage"]

print(f"状态: {payload['status'].upper()}")
print(
    "范围: "
    f"发现 {coverage['discovered_assets']} / "
    f"扫描 {coverage['scanned_assets']} / "
    f"跳过 {coverage['skipped_assets']}"
)
print(
    "结果: "
    f"{summary['findings']} Findings / "
    f"最高 {str(summary['highest_severity']).upper()} / "
    f"Hard Gate {summary['hard_gate_matches']}"
)
print(
    "策略: "
    f"{policy['enforcement_mode']}; "
    f"ci_blocking_enabled={str(policy['ci_blocking_enabled']).lower()}"
)

if detail_mode == "findings":
    print("\n证据摘要:")
    for finding in payload["assessment"]["findings"]:
        evidence = finding["evidence"][0]
        location = f"{evidence['asset_path']}:{evidence['start_line']}"
        excerpt = " ".join(evidence["excerpt"].split())
        print(
            f"- [{finding['severity'].upper()}] {finding['rule_id']} "
            f"{location} — {excerpt}"
        )
elif detail_mode == "coverage":
    print("\nCoverage Issues:")
    for issue in coverage["issues"]:
        print(f"- {issue['code']} {issue['asset_path']} — {issue['message']}")
PY
}

render_diff() {
  local report_path="$1"

  "$python_executable" - "$report_path" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = payload["summary"]
print(f"状态: {payload['status'].upper()}")
print(
    "变化: "
    f"{summary['changes']} 个资产 / "
    f"新增 {summary['added']} / 修改 {summary['modified']} / 删除 {summary['removed']}"
)
print("\n关键文本 Diff:")
for change in payload["changes"]:
    print(f"\n[{change['change_type'].upper()}] {change['path']}")
    text_diff = change.get("text_diff") or {}
    for hunk in text_diff.get("hunks", []):
        for line in hunk.get("lines", []):
            if line["kind"] not in {"added", "removed"}:
                continue
            marker = "+" if line["kind"] == "added" else "-"
            number = line["after_line_number"] or line["before_line_number"]
            text = line["text"].removesuffix("\\n").rstrip("\n")
            print(f"  {marker} L{number}: {text}")
PY
}

cd "$repository_root"

printf '%s%sAgentSec Release Agent 开发者现场 Demo%s\n' "$bold" "$cyan" "$reset"
printf '%s\n' '================================================================================'
printf '%s\n' '故事：一个只做本地只读评审的 Release Agent，其控制文件发生风险漂移。'
printf '%s\n' '目标：用 Baseline、文本 Diff 和确定性规则给出文件/行号级证据。'
printf '%s\n' '边界：全程离线、只读扫描、绝不执行 Demo 中声明的脚本或命令。'
printf '%s\n' '策略：AgentSec 0.1.0 为 report-only；发布处置由人决定。'
printf '案例语言: %s\n' "$case_language"
printf '输出目录: %s\n' "$output_dir"

heading 1 8 '环境确认'
show_command 'agentsec version'
"${agentsec[@]}" version
if [[ "$show_rules" == true ]]; then
  if [[ "$case_language" == "zh" ]]; then
    show_command 'agentsec rules list --language zh'
    "${agentsec[@]}" rules list --language zh
  else
    show_command 'agentsec rules list'
    "${agentsec[@]}" rules list
  fi
else
  note '规则列表默认不展开；需要展示时使用 --show-rules。'
fi
pause_for_next_step

heading 2 8 '扫描安全基线'
note '预期：2 个资产、Coverage Complete、0 Findings。'
run_json_command \
  "$output_dir/baseline-scan.json" 0 \
  "agentsec scan $demo_relative_root/baseline --format json" \
  scan "$baseline_root"
render_assessment "$output_dir/baseline-scan.json" summary
note '说明：0 Findings 仅代表当前支持范围未命中规则，不代表 Agent 全局安全。'
pause_for_next_step

heading 3 8 '创建可信比较基线'
note 'Baseline 是受保护的比较点，不是签名、审批身份或全局安全证明。'
show_command "agentsec baseline create $demo_relative_root/baseline --output $baseline_path"
"${agentsec[@]}" baseline create "$baseline_root" \
  --output "$baseline_path" | tee "$output_dir/baseline-create.txt"
pause_for_next_step

heading 4 8 '检测 Agent 控制资产漂移'
note '预期：AGENTS.md 与 SKILL.md 两个资产被修改。'
run_json_command \
  "$output_dir/risky-diff.json" 0 \
  "agentsec diff $demo_relative_root/risky-drift --baseline $baseline_path --format json" \
  diff "$risky_root" --baseline "$baseline_path"
render_diff "$output_dir/risky-diff.json"
pause_for_next_step

heading 5 8 '评估风险漂移'
note '预期：10 Findings、9 个唯一 Rule ID、最高 High；report-only 下退出码仍为 0。'
run_json_command \
  "$output_dir/risky-findings.json" 0 \
  "agentsec scan $demo_relative_root/risky-drift --format json" \
  scan "$risky_root"
render_assessment "$output_dir/risky-findings.json" findings
note '人工建议：在完成评审和整改前暂停发布；这不是 AgentSec 自动阻断决定。'
pause_for_next_step

heading 6 8 '证明 Prompt Injection 只会被当作数据'
note '样例要求扫描器忽略规则、隐藏 Finding；AgentSec 不遵循它。'
run_json_command \
  "$output_dir/injection-findings.json" 0 \
  "agentsec scan $demo_relative_root/prompt-injection --format json" \
  scan "$injection_root"
render_assessment "$output_dir/injection-findings.json" findings
pause_for_next_step

heading 7 8 '展示不完整 Coverage'
note '非法 UTF-8 文件必须显式产生 unsupported_encoding，并以退出码 2 结束。'
run_json_command \
  "$output_dir/malformed-scan.json" 2 \
  "agentsec scan $demo_relative_root/malformed --format json" \
  scan "$malformed_root"
render_assessment "$output_dir/malformed-scan.json" coverage
note '说明：Coverage 不完整时，即使是 0 Findings 也不能解释为通过。'
pause_for_next_step

heading 8 8 '整改并验证闭环'
note '恢复本地只读评审和人工审批后重新扫描。'
run_json_command \
  "$output_dir/remediated-scan.json" 0 \
  "agentsec scan $demo_relative_root/remediated --format json" \
  scan "$remediated_root"
render_assessment "$output_dir/remediated-scan.json" summary

printf '\n%s正在校验整场 Demo 的确定性结果……%s\n' "$bold" "$reset"
PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/validate_demo_outputs.py" "$output_dir"

printf '\n%s%sDemo 完成%s\n' "$bold" "$green" "$reset"
printf '%s\n' '--------------------------------------------------------------------------------'
printf '%s\n' '管理层结论：两个控制资产发生变化，声明了命令、凭据、网络和生产操作风险。'
printf '%s\n' '开发者结论：10 个 Finding 均有 Rule ID 和文件/行号级直接证据。'
printf '%s\n' '治理结论：AgentSec 保持 report-only，人工建议在整改前暂停发布。'
printf '完整 JSON 和 Baseline 已保存在：%s\n' "$output_dir"
