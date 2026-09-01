"""Initial reviewed Phase 1 Markdown security rule pack."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import PurePosixPath

from agentsec.domain import FindingCategory
from agentsec.parsers import MarkdownBlockKind, ObfuscationKind
from agentsec.rules.base import (
    Rule,
    RuleContext,
    RuleEvaluation,
    RuleEvidenceCandidate,
    RuleFindingCandidate,
    RuleMetadata,
    RuleScope,
    RuleTarget,
)
from agentsec.rules.matching import (
    MAX_EVIDENCE_EXCERPT_CHARACTERS,
    ContextWindow,
    KeywordRule,
    RegexCondition,
    RegexRule,
)

BUILTIN_MARKDOWN_RULE_IDS = (
    "MD-APPROVAL-001",
    "MD-DEPLOY-001",
    "MD-DESTRUCT-001",
    "MD-EXEC-001",
    "MD-EXEC-002",
    "MD-INSTR-001",
    "MD-INSTR-002",
    "MD-MEMORY-001",
    "MD-NET-001",
    "MD-OBFUSC-001",
    "MD-PRIV-001",
    "MD-PRIV-002",
    "MD-SECRET-001",
    "MD-SELF-001",
    "MD-TOOL-001",
)
BUILTIN_MARKDOWN_RULE_COUNT = len(BUILTIN_MARKDOWN_RULE_IDS)

_PROSE_BLOCKS = frozenset(
    {
        MarkdownBlockKind.HEADING,
        MarkdownBlockKind.PARAGRAPH,
        MarkdownBlockKind.LIST_ITEM,
    }
)
_ALL_BLOCKS = frozenset(MarkdownBlockKind)
_OBFUSCATION_KINDS = frozenset(
    {
        ObfuscationKind.BASE64_LIKE,
        ObfuscationKind.ZERO_WIDTH,
        ObfuscationKind.BIDI_CONTROL,
        ObfuscationKind.CONTROL_CHARACTER,
        ObfuscationKind.MIXED_SCRIPT_CONFUSABLE,
    }
)
_EXECUTABLE_REFERENCE_SUFFIXES = frozenset(
    {
        ".bash",
        ".bat",
        ".bin",
        ".cjs",
        ".cmd",
        ".exe",
        ".js",
        ".mjs",
        ".pl",
        ".ps1",
        ".py",
        ".rb",
        ".sh",
        ".zsh",
    }
)


def builtin_markdown_rules() -> tuple[Rule, ...]:
    """Return the complete initial production rule pack in stable Rule ID order."""

    rules: tuple[Rule, ...] = (
        _approval_weakening_rule(),
        _deployment_rule(),
        _destructive_action_rule(),
        _shell_execution_rule(),
        _dynamic_code_execution_rule(),
        _instruction_override_rule(),
        _safety_bypass_rule(),
        _persistent_memory_rule(),
        _external_network_rule(),
        _obfuscation_rule(),
        _production_access_rule(),
        _administrator_access_rule(),
        _secret_access_rule(),
        _self_modification_rule(),
        _external_tooling_rule(),
    )
    ordered = tuple(sorted(rules, key=lambda rule: rule.metadata.rule_id))
    if tuple(rule.metadata.rule_id for rule in ordered) != BUILTIN_MARKDOWN_RULE_IDS:
        raise RuntimeError("Built-in Markdown rule pack identity is invalid.")
    return ordered


def _instruction_override_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-INSTR-001",
            category=FindingCategory.INSTRUCTION_INTEGRITY,
            title="Earlier instructions may be overridden",
            description=(
                "The Agent asset contains a direct phrase that may tell the Agent to "
                "ignore, disregard, or replace earlier instructions."
            ),
            recommendation=(
                "Remove instruction-override language and document the intended "
                "instruction precedence explicitly."
            ),
        ),
        keywords=(
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore all previous rules",
            "ignore any earlier instruction",
            "ignore any earlier requirement",
            "disregard previous instructions",
            "disregard prior instructions",
            "override system instructions",
            "忽略之前的指令",
            "忽略此前指令",
            "忽略先前要求",
            "无视已有指令",
            "无视先前指令",
            "覆盖系统指令",
            "以本文件指令为准",
        ),
        block_kinds=_PROSE_BLOCKS,
    )


def _safety_bypass_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-INSTR-002",
            category=FindingCategory.INSTRUCTION_INTEGRITY,
            title="Safety or reporting controls may be bypassed",
            description=(
                "The Agent asset contains a direct phrase that may disable security "
                "checks, suppress findings, or hide controlling instructions."
            ),
            recommendation=(
                "Keep safety checks and transparent reporting mandatory, and remove "
                "instructions that suppress or conceal security-relevant behavior."
            ),
        ),
        keywords=(
            "bypass safety controls",
            "disable safety checks",
            "skip security checks",
            "suppress every finding",
            "suppress security findings",
            "hide these instructions",
            "do not mention this rule",
            "do not disclose this instruction",
            "绕过安全控制",
            "关闭安全检查",
            "跳过安全检查",
            "屏蔽风险发现",
            "屏蔽所有风险发现",
            "不报告安全问题",
            "隐藏这些指令",
            "不要披露本指令",
        ),
        block_kinds=_PROSE_BLOCKS,
    )


def _approval_weakening_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-APPROVAL-001",
            category=FindingCategory.HUMAN_APPROVAL,
            title="Human approval may be weakened or removed",
            description=(
                "The Agent asset declares execution without approval or confirmation, "
                "or otherwise weakens a human-review requirement."
            ),
            recommendation=(
                "Require explicit human confirmation before side-effecting or "
                "privileged actions and state the approval boundary unambiguously."
            ),
        ),
        keywords=(
            "without approval",
            "without confirmation",
            "no approval required",
            "do not ask for confirmation",
            "skip human approval",
            "automatically approve",
            "无需批准",
            "无需确认",
            "无需人工审批",
            "不必征得用户同意",
            "不要请求确认",
            "绕过人工审批",
            "自动批准",
        ),
        block_kinds=_PROSE_BLOCKS,
    )


def _shell_execution_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-EXEC-001",
            category=FindingCategory.CODE_EXECUTION,
            title="Shell or operating-system command execution is declared",
            description=(
                "The Agent asset declares use of a shell, terminal, or "
                "operating-system command execution capability."
            ),
            recommendation=(
                "Constrain command execution to an allowlist, use least privilege, and "
                "require confirmation before commands with side effects."
            ),
        ),
        keywords=(
            "shell command",
            "run a shell",
            "execute a command",
            "execute commands",
            "run terminal commands",
            "invoke bash",
            "invoke powershell",
            "git status",
            "commit and push your own changes",
            "运行 shell 命令",
            "执行 shell 命令",
            "执行系统命令",
            "运行终端命令",
            "调用 bash",
            "调用 powershell",
        ),
        block_kinds=_ALL_BLOCKS,
    )


def _dynamic_code_execution_rule() -> Rule:
    return RegexRule(
        _metadata(
            rule_id="MD-EXEC-002",
            category=FindingCategory.CODE_EXECUTION,
            title="Dynamic or arbitrary code execution is declared",
            description=(
                "The Agent asset declares eval, exec, dynamic imports, or arbitrary "
                "code execution."
            ),
            recommendation=(
                "Remove dynamic code evaluation, restrict imports to reviewed modules, "
                "and never execute code obtained from untrusted input."
            ),
        ),
        patterns=(
            r"\beval\(",
            r"\bexec\(",
            r"\bdynamic\s{1,8}import\b",
            r"\bexecute arbitrary code\b",
            r"\brun arbitrary code\b",
            r"动态执行代码",
            r"执行任意代码",
            r"动态导入模块",
            r"调用 eval\(",
            r"调用 exec\(",
        ),
        block_kinds=_ALL_BLOCKS,
    )


def _external_network_rule() -> Rule:
    metadata = _metadata(
        rule_id="MD-NET-001",
        category=FindingCategory.NETWORK_ACCESS,
        title="External network transmission or request is declared",
        description=(
            "The Agent asset declares an external API, webhook, HTTP request, or a "
            "data-transfer action supported by a nearby URL."
        ),
        recommendation=(
            "Restrict destinations to an allowlist, prohibit secret transmission, and "
            "require approval for external network side effects."
        ),
    )
    return _CompositeRule(
        metadata=metadata,
        delegates=(
            KeywordRule(
                metadata,
                keywords=(
                    "call an external api",
                    "external webhook",
                    "make an http request",
                    "make a network request",
                    "send secrets to",
                    "exfiltrate data",
                    "search the web",
                    "访问外部网络",
                    "调用外部 api",
                    "发送网络请求",
                    "向外部 webhook 推送",
                    "发送到外部",
                    "上传数据到",
                    "向外部传输数据",
                ),
                block_kinds=_ALL_BLOCKS,
            ),
            KeywordRule(
                metadata,
                keywords=(
                    "send its value",
                    "send data",
                    "upload data",
                    "upload files",
                    "post results",
                    "post data",
                    "将数据发送至",
                    "将其值发送到",
                    "上传文件到",
                    "推送结果到",
                ),
                context=ContextWindow(
                    condition=RegexCondition(
                        patterns=(
                            r"https://[A-Za-z0-9.-]{1,32}",
                            r"http://[A-Za-z0-9.-]{1,32}",
                        )
                    ),
                    before_lines=1,
                    after_lines=1,
                    include_match_line=True,
                ),
                block_kinds=_ALL_BLOCKS,
            ),
        ),
    )


def _secret_access_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-SECRET-001",
            category=FindingCategory.SECRET_ACCESS,
            title="Secret, token, credential, or environment access is declared",
            description=(
                "The Agent asset declares reading or using credentials, secrets, "
                "tokens, keys, or environment variables."
            ),
            recommendation=(
                "Use a scoped secret provider, expose only required identifiers, and "
                "never print or transmit full secret values."
            ),
        ),
        keywords=(
            "environment variable",
            "read credentials",
            "read secrets",
            "access credentials",
            "access secrets",
            "retrieve token",
            "deployment token",
            "api key",
            "private key",
            "读取环境变量",
            "读取凭证",
            "读取密钥",
            "访问密钥",
            "访问令牌",
            "获取部署凭证",
            "使用 api 密钥",
            "使用私钥",
        ),
        block_kinds=_ALL_BLOCKS,
    )


def _production_access_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-PRIV-001",
            category=FindingCategory.PRIVILEGED_ACCESS,
            title="Production-system access is declared",
            description=(
                "The Agent asset declares access to or modification of a production "
                "environment, system, database, cluster, or credential."
            ),
            recommendation=(
                "Separate production identity from analysis, use read-only access by "
                "default, and require audited approval for production changes."
            ),
        ),
        keywords=(
            "production environment",
            "production system",
            "production database",
            "production cluster",
            "production credentials",
            "write to production",
            "发布到生产环境",
            "写入生产环境",
            "修改生产数据库",
            "访问生产集群",
            "使用生产凭据",
            "生产环境",
        ),
        block_kinds=_ALL_BLOCKS,
    )


def _administrator_access_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-PRIV-002",
            category=FindingCategory.PRIVILEGED_ACCESS,
            title="Administrator, root, or elevated privilege is declared",
            description=(
                "The Agent asset declares administrator, root, sudo, or elevated "
                "privilege."
            ),
            recommendation=(
                "Remove administrator access where possible and run the Agent with a "
                "minimal, task-scoped identity."
            ),
        ),
        keywords=(
            "administrator privileges",
            "admin privileges",
            "root privileges",
            "run as root",
            "sudo access",
            "elevated privileges",
            "管理员权限",
            "root 权限",
            "以 root 身份运行",
            "sudo 权限",
            "提升权限",
        ),
        block_kinds=_ALL_BLOCKS,
    )


def _destructive_action_rule() -> Rule:
    return RegexRule(
        _metadata(
            rule_id="MD-DESTRUCT-001",
            category=FindingCategory.DESTRUCTIVE_ACTION,
            title="Destructive deletion or reset action is declared",
            description=(
                "The Agent asset declares broad deletion, destructive reset, database "
                "drop, resource destruction, or force removal."
            ),
            recommendation=(
                "Require an explicit target preview, human confirmation, backups, and "
                "a narrowly scoped allowlist before destructive actions."
            ),
        ),
        patterns=(
            r"\bdelete all\b",
            r"\bremove all files\b",
            r"\bwipe the\b",
            r"\bdrop the database\b",
            r"\brm\s{1,8}-rf\b",
            r"\bgit\s{1,8}reset --hard\b",
            r"\bforce delete\b",
            r"\bdestroy resources\b",
            r"删除所有",
            r"删除全部文件",
            r"清空数据库",
            r"删除数据库",
            r"强制删除",
            r"强制清理",
            r"销毁资源",
        ),
        block_kinds=_ALL_BLOCKS,
    )


def _deployment_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-DEPLOY-001",
            category=FindingCategory.DESTRUCTIVE_ACTION,
            title="Deployment, release, or publishing action is declared",
            description=(
                "The Agent asset declares deployment, release publication, or package "
                "publishing behavior with external side effects."
            ),
            recommendation=(
                "Require an approved release workflow, immutable artifacts, and human "
                "confirmation before deployment or publishing."
            ),
        ),
        keywords=(
            "deploy to production",
            "publish the release",
            "push the release",
            "release to production",
            "automatically deploy",
            "publish package",
            "发布生产",
            "部署到生产",
            "自动部署",
            "自动发布",
            "发布到线上",
            "发布软件包",
        ),
        block_kinds=_ALL_BLOCKS,
    )


def _persistent_memory_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-MEMORY-001",
            category=FindingCategory.PERSISTENT_MEMORY,
            title="Persistent or cross-session memory is declared",
            description=(
                "The Agent asset declares retaining information across sessions or for "
                "future tasks."
            ),
            recommendation=(
                "Minimize retained data, define expiration and deletion behavior, and "
                "exclude secrets and untrusted instructions from persistent memory."
            ),
        ),
        keywords=(
            "persist to memory",
            "persistent memory",
            "long-term memory",
            "remember across sessions",
            "store for future tasks",
            "retain across sessions",
            "持久化记忆",
            "跨会话记忆",
            "跨会话保存",
            "长期记忆",
            "保存供未来任务",
            "记住供后续任务",
        ),
        block_kinds=_PROSE_BLOCKS,
    )


def _self_modification_rule() -> Rule:
    return KeywordRule(
        _metadata(
            rule_id="MD-SELF-001",
            category=FindingCategory.SELF_MODIFICATION,
            title="Agent self-modification is declared",
            description=(
                "The Agent asset declares changing its own instructions, "
                "configuration, or Skill definitions."
            ),
            recommendation=(
                "Keep control assets read-only to the Agent and require reviewed, "
                "version-controlled changes through a separate workflow."
            ),
        ),
        keywords=(
            "modify its own instructions",
            "rewrite its instructions",
            "update this agents.md",
            "update agents.md",
            "update its own configuration",
            "edit its own skill",
            "self-modify",
            "修改自身指令",
            "修改自己的指令",
            "重写自己的配置",
            "更新自身配置",
            "编辑自身技能",
        ),
        block_kinds=_PROSE_BLOCKS,
    )


def _obfuscation_rule() -> Rule:
    return _ObfuscationIndicatorRule(
        metadata=_metadata(
            rule_id="MD-OBFUSC-001",
            category=FindingCategory.OBFUSCATION,
            title="Encoded, invisible, or confusable content is present",
            description=(
                "The parser found Base64-like, zero-width, bidirectional, control, or "
                "mixed-script content that may conceal instructions."
            ),
            recommendation=(
                "Replace hidden or encoded instructions with plain reviewed text and "
                "inspect the indicated source line without executing decoded content."
            ),
            targets=frozenset({RuleTarget.OBFUSCATION_INDICATOR}),
        )
    )


def _external_tooling_rule() -> Rule:
    metadata = _metadata(
        rule_id="MD-TOOL-001",
        category=FindingCategory.EXTERNAL_TOOLING,
        title="External tool or executable script use is declared",
        description=(
            "The Agent asset declares invoking an external tool or references a file "
            "with an executable script or binary extension."
        ),
        recommendation=(
            "Review and pin external tools, prohibit automatic installation, and allow "
            "only audited scripts with explicit approval."
        ),
        targets=frozenset({RuleTarget.MARKDOWN_BLOCK, RuleTarget.REFERENCE}),
    )
    return _ExternalToolingRule(
        metadata=metadata,
        text_rule=KeywordRule(
            metadata,
            keywords=(
                "run the script",
                "execute the script",
                "invoke external tool",
                "use external tool",
                "download and run",
                "install and execute",
                "skills provide your tools",
                "运行脚本",
                "执行脚本",
                "调用外部工具",
                "使用外部工具",
                "下载并运行",
                "安装并执行",
            ),
            block_kinds=_ALL_BLOCKS,
        ),
    )


def _metadata(
    *,
    rule_id: str,
    category: FindingCategory,
    title: str,
    description: str,
    recommendation: str,
    targets: frozenset[RuleTarget] = frozenset({RuleTarget.MARKDOWN_BLOCK}),
) -> RuleMetadata:
    """Create one immutable metadata record for all Phase 1 Markdown assets."""

    return RuleMetadata(
        rule_id=rule_id,
        title=title,
        description=description,
        category=category,
        recommendations=(recommendation,),
        scope=RuleScope.all_markdown(
            *tuple(sorted(targets, key=lambda item: item.value))
        ),
    )


@dataclass(frozen=True, slots=True)
class _CompositeRule:
    """Combine trusted delegates under one stable Rule identity."""

    metadata: RuleMetadata
    delegates: tuple[Rule, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if not self.delegates:
            raise ValueError("composite rule requires delegates")
        if any(delegate.metadata != self.metadata for delegate in self.delegates):
            raise ValueError("composite rule delegates must share metadata")

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Merge deterministic delegate candidates in source order."""

        candidates: list[RuleFindingCandidate] = []
        for delegate in self.delegates:
            candidates.extend(delegate.evaluate(context).candidates)
        ordered = tuple(
            sorted(set(candidates), key=lambda candidate: candidate._sort_key())
        )
        return RuleEvaluation(candidates=ordered)


@dataclass(frozen=True, slots=True)
class _ObfuscationIndicatorRule:
    """Convert selected parser indicators to source-backed candidates."""

    metadata: RuleMetadata

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Return one candidate per supported indicator without copying source text."""

        if not self.metadata.scope.applies_to(context.asset.asset_type):
            return RuleEvaluation()
        candidates = tuple(
            RuleFindingCandidate(
                evidence=(
                    RuleEvidenceCandidate(
                        start_line=indicator.start_line,
                        end_line=indicator.end_line,
                        field=f"obfuscation:{indicator.kind.value}",
                    ),
                )
            )
            for indicator in context.document.indicators
            if indicator.kind in _OBFUSCATION_KINDS
        )
        return RuleEvaluation(candidates=candidates)


@dataclass(frozen=True, slots=True)
class _ExternalToolingRule:
    """Match executable-tool declarations and static executable references."""

    metadata: RuleMetadata
    text_rule: KeywordRule = dataclass_field(repr=False)

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Inspect in-memory text and references without dereferencing any target."""

        if not self.metadata.scope.applies_to(context.asset.asset_type):
            return RuleEvaluation()
        candidates = list(self.text_rule.evaluate(context).candidates)
        for reference in context.document.references:
            if (
                _reference_suffix(reference.target)
                not in _EXECUTABLE_REFERENCE_SUFFIXES
            ):
                continue
            candidates.append(
                RuleFindingCandidate(
                    evidence=(
                        RuleEvidenceCandidate(
                            start_line=reference.start_line,
                            end_line=reference.end_line,
                            excerpt=_bounded_reference_excerpt(
                                reference.raw_text,
                                reference.target,
                            ),
                            field="reference:executable_script",
                        ),
                    )
                )
            )
        ordered = tuple(
            sorted(set(candidates), key=lambda candidate: candidate._sort_key())
        )
        return RuleEvaluation(candidates=ordered)


def _reference_suffix(target: str) -> str:
    """Return a normalized static suffix without resolving or opening the target."""

    normalized = target.split("#", 1)[0].split("?", 1)[0].replace("\\", "/")
    return PurePosixPath(normalized).suffix.lower()


def _bounded_reference_excerpt(raw_text: str, target: str) -> str:
    """Return an exact bounded source substring around an executable target."""

    if len(raw_text) <= MAX_EVIDENCE_EXCERPT_CHARACTERS:
        return raw_text
    target_start = raw_text.find(target)
    if target_start < 0:
        return raw_text[:MAX_EVIDENCE_EXCERPT_CHARACTERS]
    remaining = MAX_EVIDENCE_EXCERPT_CHARACTERS - min(
        len(target),
        MAX_EVIDENCE_EXCERPT_CHARACTERS,
    )
    start = max(0, target_start - remaining // 2)
    end = start + MAX_EVIDENCE_EXCERPT_CHARACTERS
    if end > len(raw_text):
        end = len(raw_text)
        start = end - MAX_EVIDENCE_EXCERPT_CHARACTERS
    return raw_text[start:end]
