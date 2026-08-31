# AgentSec 审批问题清单（待修改）

> 审批日期：2026-08-20
> 审批依据：语雀需求文档《AgentSec：AI 辅助研发执行计划与任务清单》+ 仓库实测
> 质量门禁实测：Ruff / Ruff Format（142 files）/ Mypy strict（141 files）/ Pytest 743 passed —— 全部通过

## 中等问题（代码缺陷，建议修复）

### M-01 JSON 大整数逃逸 fail-closed 契约

- **位置**：`src/agentsec/parsers/json_document.py:180`；同类问题：`src/agentsec/manifests/validation.py:101`、`src/agentsec/manifests/diff.py:578`
- **问题**：`json.loads(token)` 在 Python 3.11+ 对超过 4300 位的数字字面量抛裸 `ValueError`（非 `JSONDecodeError`），未被捕获，破坏"只抛 `StructuredParseError`"的 fail-closed 契约。独立 API 使用者会收到未类型化异常。
- **建议**：捕获 `ValueError`（`JSONDecodeError` 的父类）并统一转换为安全错误类型。

### M-02 TOML 定位扫描器 O(n²) CPU 放大

- **位置**：`src/agentsec/parsers/toml_document.py:255-266`
- **问题**：`_assignment_end` 对每条赋值逐行拼接片段反复调用 `tomllib.loads`，10 万行多行字符串会触发约 10 万次解析，总量 O(行数 × 文件大小)。1MB 文件上限内仍可造成显著 CPU 放大，与 `docs/resource-limits.md` 的 bounded-work 声明存在差距。
- **建议**：限制单条赋值的最大拼接行数/重试次数，或改用一次性扫描定位。

### M-03 指令 CONFLICT 分支为死代码，与 ADR-0023 不符

- **位置**：`src/agentsec/manifests/instructions.py:114-129`
- **问题**：每个 slot 的 `decisions` 字典至多含 BASE/OVERRIDE 两个键，两者并存已在 91-112 行处理，同类重复在 75-78 行直接抛错，故 `len(candidates) != 1` 永不为真，`resolution=conflict` 永远无法产生，与 `docs/decisions/0023-instruction-inheritance-override-resolver.md` 描述的冲突输出不符。
- **建议**：要么实现真正的冲突产出路径，要么修正 ADR-0023 描述。

### M-04 Codex 适配器把内部错误误报为解析失败

- **位置**：`src/agentsec/frameworks/codex.py:852`
- **问题**：`except Exception` 把 `_parse_candidate` 在 906 行抛出的 `FrameworkAdapterError`（适配器自身缺陷）也吞为 `PARSE_ERROR` 覆盖问题，掩盖实现 bug。
- **建议**：单独放行 `FrameworkAdapterError`，只把解析器异常映射为 `PARSE_ERROR`。

## 轻微问题（代码）

| 编号 | 位置 | 问题 |
| --- | --- | --- |
| L-01 | `src/agentsec/manifests/configuration.py:115-121` | PLUGIN scope 候选落入 `else` 分支，reason 被误标为 `NESTED_PROJECT` |
| L-02 | `src/agentsec/manifests/relationships.py:306-313` | `_target_id` 无条件 strip `sub-agent:`/`subagent:` 前缀；prefix 为 `relation`（kind=OTHER）时走 `else` 分支错误 strip `memory:`，可能改写目标名 |
| L-03 | `src/agentsec/parsers/mcp_document.py:691` | `is_local` 仅匹配 `localhost/127.0.0.1/::1`，`127.0.0.2`、`[::ffff:127.0.0.1]` 等环回地址误判为 EXTERNAL（方向保守，仅分类不准） |
| L-04 | `src/agentsec/manifests/capabilities.py:88`、`src/agentsec/manifests/relationships.py:117` | 跨模块调用私有方法 `AssociationExtractor._pair_sources`，且两处各自重复执行完整的 `AssociationExtractor().extract`（结果确定但冗余，耦合私有 API） |
| L-05 | `src/agentsec/manifests/builder.py:380-388` | inspection 中无任何 project 资产时，`subject_root_id` 校验静默通过，可接受任意值 |
| L-06 | `src/agentsec/manifests/unknowns.py:77-78` | 生成的 unknown_id 与既有 unknown 冲突时 `setdefault` 静默保留旧值，可能掩盖变化 |
| L-07 | `src/agentsec/parsers/mcp_document.py:397-401` | `_direct_children` 每次全表扫描 `document.nodes`，server 多时呈 O(servers×nodes)（有 `max_servers=256` 上限，仅性能问题） |
| L-08 | `src/agentsec/parsers/json_document.py:150-174` | `true/false/null` 用 `startswith` 匹配且无词边界检查，目前靠后续字符校验兜底，逻辑正确但脆弱 |

## 流程与治理问题

### P-01 需求文档任务状态表未维护

- **位置**：语雀需求文档第 14 节
- **问题**：状态表只有 P0/P1 行；M1-01 和 P2-01～P2-11 的完成记录散落在第 10 节正文中，状态表失去"持续维护"的作用。
- **建议**：将 M1-01、P2-01～P2-11 补入状态表（状态/Owner/完成时间/备注）。

### P-02 发布制品与源码脱节

- **位置**：`dist/`、`src/agentsec/versioning.py:8`、`CHANGELOG.md`
- **问题**：`dist/` 仍是 0.1.0 / Rule Pack 0.2.0 冻结制品，而源码已是 Rule Pack 0.3.0 + Phase 2 主链路（P2-01～P2-11）；`PACKAGE_VERSION` 仍为 `0.1.0`，M1-01 和 P2 全部挂在 CHANGELOG "Unreleased"。
- **建议**：尽快规划 0.2.0 版本发布评审，拆分 Unreleased 段落为正式版本记录。

### P-03 无 Git 溯源

- **位置**：整个工作区
- **问题**：仓库不是 Git 仓库，所有任务记录为"本地未提交"，无法审计变更历史、无法签名溯源。文档已如实声明，但属于供应链治理风险。
- **建议**：尽快初始化 Git 仓库并配置远程托管。

## 审批结论

**有条件通过**。文档声明与实际状态一致，质量门禁全部真实通过，安全不变量成立，无严重问题。

后续建议优先顺序：

1. 修复 M-01～M-04 中等级别代码缺陷（重点：M-01 fail-closed 契约、M-03 死代码/ADR 不一致）；
2. 补齐任务状态表（P-01）；
3. 进入 Phase 2 集成收尾前完成 0.2.0 版本发布评审（P-02）；
4. 建立 Git 仓库溯源（P-03）。
