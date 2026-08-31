#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
language="en"
output_dir=""
pause_enabled=true
offline=false

usage() {
  cat <<'USAGE'
Usage: scripts/demo-capability-drift.sh [OPTIONS]

Run the presenter-friendly P2I-05 Capability Drift story.

Options:
  --language L       Demo language/assets: en or zh (default: en).
  --no-pause         Do not wait for Enter between story stages.
  --offline          Use frozen expected artifacts and verify checksums.
  --output-dir DIR   Preserve live artifacts in a new or empty directory.
  --python PATH      Use a specific Python 3.12 executable.
  -h, --help         Show this help message.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --language)
      [[ $# -ge 2 ]] || { echo "Missing value for --language" >&2; exit 2; }
      language="$2"
      shift 2
      ;;
    --no-pause)
      pause_enabled=false
      shift
      ;;
    --offline)
      offline=true
      shift
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for --output-dir" >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || { echo "Missing value for --python" >&2; exit 2; }
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

if [[ "$language" != "en" && "$language" != "zh" ]]; then
  echo "Unsupported language: $language (expected en or zh)" >&2
  exit 2
fi
if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  exit 2
fi
if [[ ! -t 0 ]]; then
  pause_enabled=false
fi

if [[ "$language" == "zh" ]]; then
  demo_relative_root="demos/capability-drift-agent-zh"
else
  demo_relative_root="demos/capability-drift-agent"
fi
demo_root="$repository_root/$demo_relative_root"

if [[ "$offline" == true ]]; then
  artifact_dir="$demo_root/expected"
  PYTHONPATH="$repository_root/src" "$python_executable" \
    "$repository_root/scripts/validate_capability_demo_outputs.py" \
    "$artifact_dir" >/dev/null
else
  if [[ -z "$output_dir" ]]; then
    output_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentsec-capability-presenter.XXXXXX")"
  fi
  "$repository_root/scripts/run-capability-demo.sh" \
    --language "$language" \
    --output-dir "$output_dir" \
    --python "$python_executable" >/dev/null
  PYTHONPATH="$repository_root/src" "$python_executable" \
    "$repository_root/scripts/run-report-only-gate-demo.py" \
    --language "$language" \
    --format json \
    --output "$output_dir/report-only-gate-demo.json" >/dev/null
  PYTHONPATH="$repository_root/src" "$python_executable" \
    "$repository_root/scripts/run-report-only-gate-demo.py" \
    --language "$language" \
    --format text \
    --output "$output_dir/report-only-gate-demo.txt" >/dev/null
  artifact_dir="$output_dir"
fi

heading() {
  printf '\n[%s/8] %s\n' "$1" "$2"
  printf '%s\n' '--------------------------------------------------------------------------------'
}

pause_next() {
  if [[ "$pause_enabled" == true ]]; then
    if [[ "$language" == "zh" ]]; then
      printf '\n按 Enter 继续下一步，Ctrl-C 可安全退出……'
    else
      printf '\nPress Enter for the next step; Ctrl-C exits safely...'
    fi
    IFS= read -r _
  fi
}

show_command() {
  printf '\n$ %s\n' "$1"
}

render_assessment() {
  "$python_executable" - "$1" "$language" <<'PY'
import json, sys
from pathlib import Path
p=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
zh=sys.argv[2] == "zh"
s=p["summary"]
print(("状态" if zh else "Status") + f": {p['status'].upper()}")
print(("发现项" if zh else "Findings") + f": {s['findings']}")
print(("最高严重性" if zh else "Highest severity") + f": {str(s['highest_severity']).upper()}")
print(("Coverage" if zh else "Coverage") + f": {'COMPLETE' if s['manifest_coverage_complete'] else 'INCOMPLETE'}")
print(("策略" if zh else "Policy") + ": report_only; ci_blocking_enabled=false")
ids=sorted({item["rule_id"] for item in p["findings"]})
if ids:
    print(("规则" if zh else "Rules") + ": " + ", ".join(ids))
    print("\n" + ("证据示例" if zh else "Evidence examples") + ":")
    for item in p["findings"][:3]:
        ev=item["evidence"][0]
        location=f"{ev['path']}:{ev['start_line'] or '-'}"
        title=next(t["title"] for t in item["texts"] if t["language"] == sys.argv[2])
        print(f"- [{item['severity'].upper()}] {item['rule_id']} {location} — {title}")
PY
}

render_manifest() {
  "$python_executable" - "$1" "$language" <<'PY'
import json, sys
from pathlib import Path
p=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
zh=sys.argv[2] == "zh"
labels=("来源", "工具", "权限", "控制", "身份", "关系", "Unknown") if zh else ("Sources", "Tools", "Permissions", "Controls", "Identities", "Relationships", "Unknowns")
values=(len(p["sources"]),len(p["tools"]["tools"]),len(p["permissions"]["permissions"]),len(p["controls"]["controls"]),len(p["runtime_identities"]["identities"]),len(p["relationships"]["relations"]),len(p["unknowns"]))
print(("Agent" if zh else "Agent") + f": {p['identity']['agent_id']}")
print(("Coverage" if zh else "Coverage") + f": {'COMPLETE' if p['coverage']['complete'] else 'INCOMPLETE'}")
print(" / ".join(f"{k}={v}" for k,v in zip(labels,values,strict=True)))
PY
}

render_diff() {
  "$python_executable" - "$1" "$language" <<'PY'
import json, sys
from pathlib import Path
p=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
zh=sys.argv[2] == "zh"
print(("状态" if zh else "Status") + f": {'COMPLETE' if p['complete'] else 'INCOMPLETE'}")
print(("能力变化" if zh else "Capability changes") + f": {len(p['changes'])}")
print(f"added={p['added_count']} removed={p['removed_count']} modified={p['modified_count']}")
print("\n" + ("关键变化" if zh else "Key changes") + ":")
important=[c for c in p["changes"] if c["dimension"] != "unknown"]
for c in important[:10]:
    print(f"- [{c['change_type'].upper()}] {c['dimension']} {c['item_id']}")
PY
}

render_impact() {
  "$python_executable" - "$1" "$language" <<'PY'
import json, sys
from pathlib import Path
p = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
s = p["summary"]
print(
    "Finding Delta: "
    f"added={s['added_findings']} resolved={s['resolved_findings']} "
    f"changed={s['changed_findings']} unchanged={s['unchanged_findings']}"
)
print(
    ("Exposure" if sys.argv[2] == "en" else "暴露方向") + ": "
    f"increased={s['increased_exposure']} reduced={s['reduced_exposure']} "
    f"uncertain={s['uncertain']}"
)
print(
    ("Severity" if sys.argv[2] == "en" else "最高严重性") + ": "
    f"{s['highest_before_severity']} -> {s['highest_after_severity']}"
)
PY
}

if [[ "$language" == "zh" ]]; then
  title1="背景与安全边界"
  title2="经过评审的安全基线"
  title3="风险能力漂移"
  title4="Capability Diff：从文件变化到能力变化"
  title5="不完整 Coverage"
  title6="整改切断风险链"
  title7="管理层结论"
  title8="已通过资格的 Report-only Gate"
else
  title1="Context and security boundary"
  title2="Reviewed safe baseline"
  title3="Risky capability drift"
  title4="Capability Diff: from file change to capability change"
  title5="Incomplete Coverage"
  title6="Remediation breaks the risk chain"
  title7="Management close"
  title8="Qualified Report-only Gate"
fi

heading 1 "$title1"
show_command "agentsec capability rules list --language $language"
if [[ "$language" == "zh" ]]; then
  echo "AgentSec 只分析静态声明，不执行 Skill、Command 或 MCP，不证明运行时漏洞。"
else
  echo "AgentSec analyzes static declarations only; it executes no Skill, Command, or MCP and proves no runtime exploit."
fi
pause_next

heading 2 "$title2"
show_command "agentsec manifest $demo_relative_root/baseline --agent-id release-agent"
render_manifest "$artifact_dir/baseline.manifest.json"
render_assessment "$artifact_dir/baseline.assessment.json"
pause_next

heading 3 "$title3"
show_command "agentsec capability assess $demo_relative_root/risky-drift --agent-id release-agent"
render_assessment "$artifact_dir/risky-drift.assessment.json"
pause_next

heading 4 "$title4"
show_command "agentsec capability diff --before baseline.manifest.json --after risky.manifest.json"
render_diff "$artifact_dir/risky.diff.json"
show_command "agentsec capability impact --before baseline.manifest.json --after risky.manifest.json"
render_impact "$artifact_dir/risky.impact.json"
pause_next

heading 5 "$title5"
show_command "agentsec capability assess $demo_relative_root/incomplete --agent-id release-agent"
render_assessment "$artifact_dir/incomplete.assessment.json"
if [[ "$language" == "zh" ]]; then
  echo "退出码为 2；零 Finding 不能被解释为安全通过。"
else
  echo "Exit code is 2; zero Findings cannot be interpreted as a clean pass."
fi
pause_next

heading 6 "$title6"
show_command "agentsec capability assess $demo_relative_root/remediated --agent-id release-agent"
render_assessment "$artifact_dir/remediated.assessment.json"
render_diff "$artifact_dir/remediation.diff.json"
pause_next

heading 7 "$title7"
if [[ "$language" == "zh" ]]; then
  cat <<'EOF'
新增能力：执行、Secret 访问、外部网络、凭证化外部身份、委派和持久化。
最高报告风险：High；17 个 Findings，覆盖 16 个 Capability Rule ID。
整改结果：移除外部 MCP、凭证引用、委派和持久化后回到 0 Findings。
治理结论：建议人工暂停发布直至整改完成；AgentSec 本身仍为 Report-only。
EOF
else
  cat <<'EOF'
Added capabilities: execution, secret access, external network, credentialed external identity, delegation, and persistence.
Highest reported risk: High; 17 Findings across 16 Capability Rule IDs.
Remediation result: removing external MCP, credential reference, delegation, and persistence returns to 0 Findings.
Governance conclusion: humans should hold release until remediation; AgentSec itself remains report-only.
EOF
fi

heading 8 "$title8"
show_command "scripts/run-report-only-gate-demo.sh --language $language --format text"
cat "$artifact_dir/report-only-gate-demo.txt"
printf '\nArtifacts: %s\n' "$artifact_dir"
