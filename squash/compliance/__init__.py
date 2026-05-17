"""squash.compliance — multi-framework clause-level compliance scanning."""

from squash.compliance.scanner import (
    ComplianceFramework,
    ComplianceReport,
    ComplianceScanner,
    FrameworkResult,
    Requirement,
    RequirementMatch,
    builtin_requirements,
)

__all__ = [
    "ComplianceFramework",
    "ComplianceReport",
    "ComplianceScanner",
    "FrameworkResult",
    "Requirement",
    "RequirementMatch",
    "builtin_requirements",
]
