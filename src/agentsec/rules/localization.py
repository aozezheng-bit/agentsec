"""Trusted display localization for the deterministic Rule inventory."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from agentsec.domain import FindingCategory

CHINESE_CATEGORY_LABELS: Mapping[FindingCategory, str] = MappingProxyType(
    {
        FindingCategory.INSTRUCTION_INTEGRITY: "指令完整性",
        FindingCategory.HUMAN_APPROVAL: "人工审批",
        FindingCategory.CODE_EXECUTION: "代码执行",
        FindingCategory.NETWORK_ACCESS: "网络访问",
        FindingCategory.SECRET_ACCESS: "凭据访问",
        FindingCategory.PRIVILEGED_ACCESS: "特权访问",
        FindingCategory.DESTRUCTIVE_ACTION: "破坏性操作",
        FindingCategory.PERSISTENT_MEMORY: "持久记忆",
        FindingCategory.SELF_MODIFICATION: "自我修改",
        FindingCategory.OBFUSCATION: "混淆隐藏",
        FindingCategory.EXTERNAL_TOOLING: "外部工具",
    }
)

CHINESE_RULE_TITLES: Mapping[str, str] = MappingProxyType(
    {
        "MD-APPROVAL-001": "人工审批可能被弱化或移除",
        "MD-DEPLOY-001": "声明了部署、发布或制品发布操作",
        "MD-DESTRUCT-001": "声明了破坏性删除或重置操作",
        "MD-EXEC-001": "声明了 Shell 或操作系统命令执行",
        "MD-EXEC-002": "声明了动态或任意代码执行",
        "MD-INSTR-001": "可能覆盖或忽略先前指令",
        "MD-INSTR-002": "可能绕过安全检查或隐藏报告",
        "MD-MEMORY-001": "声明了持久化或跨会话记忆",
        "MD-NET-001": "声明了外部网络请求或数据传输",
        "MD-OBFUSC-001": "存在编码、不可见或易混淆内容",
        "MD-PRIV-001": "声明了生产系统访问",
        "MD-PRIV-002": "声明了管理员、Root 或提权权限",
        "MD-SECRET-001": "声明了凭据、令牌、密钥或环境变量访问",
        "MD-SELF-001": "声明了 Agent 自我修改",
        "MD-TOOL-001": "声明了外部工具或可执行脚本使用",
    }
)


def chinese_category_label(category: FindingCategory) -> str:
    """Return the reviewed Chinese display label for one Finding category."""

    return CHINESE_CATEGORY_LABELS[category]


def chinese_rule_title(rule_id: str) -> str:
    """Return the reviewed Chinese display title for one stable Rule ID."""

    return CHINESE_RULE_TITLES[rule_id]
