"""Reviewed Phase 1 rule-specific base risk profiles."""

from __future__ import annotations

from agentsec.domain import FindingCategory, ImpactLevel, LikelihoodLevel
from agentsec.risk.models import ImpactDimension, ImpactRating, RiskProfile
from agentsec.rules.builtin import BUILTIN_MARKDOWN_RULE_IDS

_DIRECT_STATIC_LIKELIHOOD = (
    "A deterministic Markdown rule matched a direct Agent control-asset declaration.",
    "Phase 1 does not prove runtime capability, reachability, exposure, or "
    "successful exploitation; the reviewed v0 profile therefore uses Moderate "
    "rather than High or Very High likelihood.",
)
_INDIRECT_STATIC_LIKELIHOOD = (
    "The rule matched an indirect indicator or executable reference rather than "
    "a verified runtime action.",
    "Additional capability, reachability, trust, or execution conditions remain "
    "unverified; the reviewed v0 profile therefore uses Low likelihood.",
)


def builtin_risk_profiles() -> tuple[RiskProfile, ...]:
    """Return the complete reviewed Risk Model v0 profile inventory."""

    profiles = (
        _profile(
            "MD-APPROVAL-001",
            FindingCategory.HUMAN_APPROVAL,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.BUSINESS_COMPLIANCE,
                ImpactLevel.HIGH,
                "Removing human approval can bypass required change-control, audit, "
                "or compliance decisions.",
            ),
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Unreviewed actions can propagate to tools and downstream systems.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.HIGH,
                "Actions without confirmation can modify code, configuration, or "
                "business state.",
            ),
        ),
        _profile(
            "MD-DEPLOY-001",
            FindingCategory.DESTRUCTIVE_ACTION,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.BUSINESS_COMPLIANCE,
                ImpactLevel.HIGH,
                "Unauthorized releases can create material operational and "
                "compliance impact.",
            ),
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.VERY_HIGH,
                "A release or publication can propagate to production users, "
                "packages, or supply-chain consumers.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.VERY_HIGH,
                "Deployment or publishing can directly change production artifacts "
                "and system state.",
            ),
        ),
        _profile(
            "MD-DESTRUCT-001",
            FindingCategory.DESTRUCTIVE_ACTION,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.AVAILABILITY,
                ImpactLevel.VERY_HIGH,
                "Broad deletion, reset, or destruction can make systems or data "
                "unavailable.",
            ),
            _impact(
                ImpactDimension.BUSINESS_COMPLIANCE,
                ImpactLevel.HIGH,
                "Irrecoverable loss can cause operational, legal, and audit impact.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.VERY_HIGH,
                "Destructive actions can irreversibly alter repositories, databases, "
                "or infrastructure.",
            ),
        ),
        _profile(
            "MD-EXEC-001",
            FindingCategory.CODE_EXECUTION,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.AVAILABILITY,
                ImpactLevel.HIGH,
                "Shell commands can stop services, consume resources, or delete "
                "required files.",
            ),
            _impact(
                ImpactDimension.CONFIDENTIALITY,
                ImpactLevel.HIGH,
                "Shell access can read locally available sensitive data and "
                "credentials.",
            ),
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Operating-system commands can affect connected tools and build or "
                "deployment environments.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.VERY_HIGH,
                "Arbitrary operating-system commands can modify code, configuration, "
                "and host state.",
            ),
        ),
        _profile(
            "MD-EXEC-002",
            FindingCategory.CODE_EXECUTION,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.AVAILABILITY,
                ImpactLevel.HIGH,
                "Dynamic code can disrupt the Agent or its host process.",
            ),
            _impact(
                ImpactDimension.CONFIDENTIALITY,
                ImpactLevel.HIGH,
                "Dynamic code can access data available to the Agent process.",
            ),
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Executed code can invoke other reachable tools and dependencies.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.VERY_HIGH,
                "Dynamic or arbitrary code execution can fully alter process and "
                "host-controlled state.",
            ),
        ),
        _profile(
            "MD-INSTR-001",
            FindingCategory.INSTRUCTION_INTEGRITY,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Instruction precedence changes can redirect later tool and Agent "
                "decisions.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.HIGH,
                "Overriding trusted instructions can alter intended security and task "
                "behavior.",
            ),
        ),
        _profile(
            "MD-INSTR-002",
            FindingCategory.INSTRUCTION_INTEGRITY,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.BUSINESS_COMPLIANCE,
                ImpactLevel.HIGH,
                "Suppressing security checks or findings can defeat review and audit "
                "requirements.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.HIGH,
                "Bypassing safety controls can change security-significant Agent "
                "behavior.",
            ),
        ),
        _profile(
            "MD-MEMORY-001",
            FindingCategory.PERSISTENT_MEMORY,
            LikelihoodLevel.LOW,
            _INDIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.CONFIDENTIALITY,
                ImpactLevel.HIGH,
                "Cross-session retention can expose secrets, personal data, or "
                "sensitive task context beyond its intended lifetime.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.MODERATE,
                "Persisted untrusted instructions can influence future Agent tasks.",
            ),
        ),
        _profile(
            "MD-NET-001",
            FindingCategory.NETWORK_ACCESS,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.CONFIDENTIALITY,
                ImpactLevel.HIGH,
                "External transmission can disclose repository, user, or operational "
                "data.",
            ),
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "External requests can affect third-party services and cross a trust "
                "boundary.",
            ),
        ),
        _profile(
            "MD-OBFUSC-001",
            FindingCategory.OBFUSCATION,
            LikelihoodLevel.LOW,
            _INDIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.MODERATE,
                "Encoded, invisible, or confusable content can conceal a change to "
                "instruction meaning, but the indicator alone proves no action.",
            ),
        ),
        _profile(
            "MD-PRIV-001",
            FindingCategory.PRIVILEGED_ACCESS,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.AVAILABILITY,
                ImpactLevel.HIGH,
                "Production access can disrupt services relied on by users.",
            ),
            _impact(
                ImpactDimension.BUSINESS_COMPLIANCE,
                ImpactLevel.HIGH,
                "Production changes can cause material operational and regulatory "
                "impact.",
            ),
            _impact(
                ImpactDimension.CONFIDENTIALITY,
                ImpactLevel.HIGH,
                "Production systems can contain sensitive user and business data.",
            ),
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.VERY_HIGH,
                "Production access can affect many users, services, tenants, or "
                "dependent systems.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.VERY_HIGH,
                "Production write capability can directly alter live code, data, or "
                "business state.",
            ),
        ),
        _profile(
            "MD-PRIV-002",
            FindingCategory.PRIVILEGED_ACCESS,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.AVAILABILITY,
                ImpactLevel.HIGH,
                "Administrator or root authority can disable services and controls.",
            ),
            _impact(
                ImpactDimension.CONFIDENTIALITY,
                ImpactLevel.VERY_HIGH,
                "Administrator or root authority can access broadly scoped sensitive "
                "data and credentials.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.VERY_HIGH,
                "Elevated privilege can modify system-wide code, policy, identity, and "
                "configuration.",
            ),
        ),
        _profile(
            "MD-SECRET-001",
            FindingCategory.SECRET_ACCESS,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.CONFIDENTIALITY,
                ImpactLevel.VERY_HIGH,
                "Credential or secret access can expose authentication material and "
                "protected data.",
            ),
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Compromised credentials can extend access to downstream services and "
                "identities.",
            ),
        ),
        _profile(
            "MD-SELF-001",
            FindingCategory.SELF_MODIFICATION,
            LikelihoodLevel.MODERATE,
            _DIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Persistent control-asset changes can alter later tasks and delegated "
                "Agent behavior.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.VERY_HIGH,
                "Changing its own instructions, configuration, or Skills can defeat "
                "reviewed control state.",
            ),
        ),
        _profile(
            "MD-TOOL-001",
            FindingCategory.EXTERNAL_TOOLING,
            LikelihoodLevel.LOW,
            _INDIRECT_STATIC_LIKELIHOOD,
            _impact(
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Unreviewed tools or scripts can introduce dependency and supply-chain "
                "effects.",
            ),
            _impact(
                ImpactDimension.INTEGRITY,
                ImpactLevel.HIGH,
                "Executable tooling can modify the workspace or runtime when invoked.",
            ),
        ),
    )
    ordered = tuple(sorted(profiles, key=lambda item: item.rule_id))
    if tuple(profile.rule_id for profile in ordered) != BUILTIN_MARKDOWN_RULE_IDS:
        raise RuntimeError("Built-in risk profile identity is invalid.")
    return ordered


def _profile(
    rule_id: str,
    category: FindingCategory,
    likelihood: LikelihoodLevel,
    likelihood_basis: tuple[str, ...],
    *impact_ratings: ImpactRating,
) -> RiskProfile:
    return RiskProfile(
        rule_id=rule_id,
        category=category,
        likelihood=likelihood,
        likelihood_basis=likelihood_basis,
        impact_ratings=impact_ratings,
    )


def _impact(
    dimension: ImpactDimension,
    level: ImpactLevel,
    rationale: str,
) -> ImpactRating:
    return ImpactRating(dimension=dimension, level=level, rationale=rationale)
