"""Squash compliance gate via pulumi_command.

Runs `squash attest` on a model artefact. Pulumi gates downstream
resources on attestation success — same pattern as the TypeScript and
Terraform examples, just rendered in Python.
"""

import json
import os
from pathlib import Path

import pulumi
import pulumi_command as command

cfg = pulumi.Config()
MODEL_PATH = cfg.require("modelPath")
MIN_SCORE = float(cfg.get_float("minScore") or 85.0)

RECORD_PATH = f"/tmp/squash-{pulumi.get_stack()}-master.json"

# Re-run when the model file changes.
_trigger = (
    Path(MODEL_PATH).stat().st_mtime if os.path.exists(MODEL_PATH) else 0
)

attest = command.local.Command(
    "squash-attest",
    create=(
        f"squash attest {MODEL_PATH} "
        "--policy eu-ai-act --policy iso-42001 "
        "--fail-on-violation "
        f"--json-result {RECORD_PATH}"
    ),
    triggers=[str(_trigger)],
)


def _parse(_stdout: str) -> dict:
    if not os.path.exists(RECORD_PATH):
        raise RuntimeError("squash attest produced no master record")
    with open(RECORD_PATH, encoding="utf-8") as fh:
        rec = json.load(fh)
    if not rec.get("passed"):
        raise RuntimeError(
            f"compliance gate failed: passed=false (id={rec.get('attestation_id')})"
        )
    if rec.get("overall_score", 0) < MIN_SCORE:
        raise RuntimeError(
            f"compliance gate failed: score {rec['overall_score']} < {MIN_SCORE} "
            f"(id={rec.get('attestation_id')})"
        )
    return rec


result = attest.stdout.apply(_parse)

pulumi.export("attestation_id", result.apply(lambda r: r["attestation_id"]))
pulumi.export("overall_score", result.apply(lambda r: r["overall_score"]))
pulumi.export("passed", result.apply(lambda r: r["passed"]))
