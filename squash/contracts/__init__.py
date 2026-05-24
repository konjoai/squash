"""squash.contracts — contract-text primitives: obligations, diff."""

from squash.contracts.obligations import (
    MODAL_WEIGHTS,
    Obligation,
    ObligationExtractor,
    extract_obligations,
)
from squash.contracts.diff import (
    ClauseChange,
    ContractDiff,
    ContractDiffer,
    diff_contracts,
)

__all__ = [
    "ClauseChange",
    "ContractDiff",
    "ContractDiffer",
    "MODAL_WEIGHTS",
    "Obligation",
    "ObligationExtractor",
    "diff_contracts",
    "extract_obligations",
]
