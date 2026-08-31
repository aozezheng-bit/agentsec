# AgentSec 接入指南（0.4.0 内部接入版）

- 适用版本：AgentSec `0.4.0`（Phase 3 Ready Candidate，`candidate_go` 2026-08-31）
- 读者：准备在团队项目中使用 AgentSec 的开发 / 安全 / SRE 同学
- 版本状态：**本地候选版**（未经远程发布；尚未声明制品签名与 SLSA 溯源）
- 上位文档：详细命令与输出解释见 `docs/poc-usage.md`；本文只讲"从零到接入"的最短路径

> 核心理解（先读这句）：AgentSec 报告的是 Agent 控制资产（AGENTS.md、Skill、
> MCP 配置等）中的**安全声明**，并输出可解释、可复现的证据。它默认**只报告
> 不阻断**；是否阻断由你们的接入方式决定。它不证明运行时被利用，也不声明
> "Agent 全局安全"。

---

## 0. 五分钟判断你是否需要它

| 你的场景 | 建议 |
| --- | --- |
| 仓库里有 AGENTS.md / Codex 或 Homi workspace / Skill / MCP 配置 | ✅ 适用 |
| 只有普通业务代码，无任何 Agent 控制资产 | ❌ 暂无收益 |
| 想"一键判断 Agent 有没有漏洞" | ⚠️ 没有这种功能；AgentSec 给的是带证据的声明清单，需要人看报告 |

## 1. 安装（内部渠道）

```bash
# 方式A：内部 pip 索引（推荐，发布后可用；见第 8 节当前限制）
pip install agentsec==0.4.0

# 方式B：直接从候选制品目录安装（当前可用）
pip install <AgentSec 仓库>/dist/0.4.0/agentsec-0.4.0-py3-none-any.whl

# 验证（应输出 agentsec 0.4.0）
agentsec version
```

环境要求：Python 3.12+。无网络依赖（扫描过程不联网、不执行被扫内容）。

## 2. 首次扫描（3 分钟看到价值）

```bash
# 进入你想检查的 Agent 项目根目录（本文用 $PROJECT 指代）
cd $PROJECT

# 报告模式跑一次（默认 exit 0，不影响任何流程）
agentsec scan .

# 想要机器可读结果给下游工具
agentsec scan . --report-format json --output agentsec-report.json
# SARIF 可直接导入代码平台的 Security 面板
agentsec scan . --report-format sarif --output agentsec.sarif
```

看报告时关注三块：**Findings**（风险声明，每条带文件/行号/证据）、
**Coverage**（哪些文件没扫到、为什么——覆盖不完整是 exit 2 的唯一来源）、
**摘要**（各级别计数）。

## 3. 建基线（开始管住变更）

```bash
# 在你认可的安全状态下打基线
agentsec baseline create . --output baseline.json
# baseline.json 建议提交进你的仓库（含资产哈希，不含敏感值）

# 之后每次变更查看漂移（新增了什么能力/权限）
agentsec diff . --baseline baseline.json
```

价值场景：PR 里 AGENTS.md "顺手"加了一句 `run scripts without approval`
——下次 diff 会以 Capability 变化明确呈现，而不是藏在几行 Markdown 里。

## 4. 能力画像（Agent 到底被授权了什么）

```bash
agentsec manifest .                      # 结构化能力画像
agentsec capability assess .             # 能力评估
agentsec score . --before baseline.json  # 综合评分（报告制）
```

## 5. CI 接入（自主决定阻断强度）

```bash
# 阈值阻断（示例：high 及以上失败，exit 1）
agentsec scan . --fail-on high

# 组织策略阻断（推荐团队统一规则时）
agentsec scan . --policy org-policy.yaml --fail-on high
```

退出码约定：`0` 无阻断项；`1` 存在达到阈值的 Finding；`2` 扫描不完整
（**先把 Coverage 补齐再谈阻断**，不要 ignore exit 2）；`3+` 配置/环境类错误。

CI 流水线建议先跑 2~4 周纯报告（不 fail），观察误报率后再开阻断。

## 6. 语义分析（Shadow，只看不动）

适用于 Codex 类 workspace（项目根含 `AGENTS.md`）：

```bash
# 离线模式：不联网、零成本，生成语义候选供人审
agentsec semantic analyze .
```

注：未识别到 Agent 结构的项目会安全退出（CONFIGURATION_ERROR）——先确认
`agentsec manifest .` 能产出画像再做语义分析。

边界须知：语义输出**只做参考证据**，永不参与阻断决策（这是架构红线）。
当前真实模型质量为基线水平（P/R≈0.39，见 ADR-0096），定义为"帮人发现
可疑点"，不作为任何决策依据。

## 7. 与你们现有流程的对接位

| 对接点 | 做法 |
| --- | --- |
| 代码平台 PR 检查 | SARIF 输出 → 平台 Security Tab |
| 告警分派 | JSON 报告 → 解析 rule_id/级别 → 路由到负责人 |
| 误报反馈 | 记录 case → 提交给 AgentSec 维护方（校准闭环入口，见 `calibration/`） |
| 合规报告 | `--report-format json` 版本化留档（同输入同输出，可复现） |

## 8. 当前限制（诚实清单，接入前必读）

1. **未远程发布**：制品只在本地 `dist/0.4.0/`（接入方式 B）；内部索引待建；
2. **未声明签名/SLSA**：安装前可对 `SHA256SUMS` 手工校验；
3. **阻断决策需组织确认**：`--fail-on` 谁有权开、开到什么级别，属安全治理
   决策，不是工程默认；
4. **语义质量为基线**：LLM 判断质量持续迭代中，Shadow-only；
5. **框架覆盖**：Homi / Codex 类 workspace 最完整；其他框架的适配器待扩展
   （见 `docs/current-architecture.md` 的框架接缝设计）。

## 9. 常见问题速查

- **exit 2?** → 看 Coverage 章节，通常是超大文件/非法编码/被排除的路径；
- **误报太多?** → 走反馈闭环（第 7 节），不要 local 静默改规则（规则包是
  版本化的，改要走评审）；
- **想豁免某条告警?** → 组织 Policy 的 Waiver 机制（Owner + 理由 + 到期日，
  过期自动失效），不要注释掉规则。

---

## 附：接入健康度自查（两周后回看）

- [ ] 扫描覆盖率是否 100%（无 exit 2）？
- [ ] 团队是否有人每周看一次报告（有归属人）？
- [ ] 误报是否进了反馈通道？
- [ ] 基线是否随可信变更同步更新？
- [ ] 是否决定开启阻断（`--fail-on`）？依据什么误报率数据？
