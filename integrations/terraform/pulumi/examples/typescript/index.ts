// Squash compliance gate via @pulumi/command.
//
// Runs `squash attest` on a model artefact. The Pulumi resource graph
// gates downstream resources (model deployments, image promotions, API
// gateway rules) on the attestation succeeding.

import * as pulumi from "@pulumi/pulumi";
import * as command from "@pulumi/command";
import * as fs from "fs";

const cfg = new pulumi.Config();
const modelPath = cfg.require("modelPath");
const minScore = cfg.getNumber("minScore") ?? 85;

const recordPath = `/tmp/squash-${pulumi.getStack()}-master.json`;

const attest = new command.local.Command("squash-attest", {
    create: pulumi.interpolate`squash attest ${modelPath} \
        --policy eu-ai-act --policy iso-42001 \
        --fail-on-violation \
        --json-result ${recordPath}`,
    triggers: [
        // re-run when the model file changes
        fs.existsSync(modelPath) ? fs.statSync(modelPath).mtime.toISOString() : "",
    ],
});

// Parse the attestation result and enforce the gate.
const result = attest.stdout.apply(_ => {
    if (!fs.existsSync(recordPath)) {
        throw new Error("squash attest produced no master record");
    }
    const rec = JSON.parse(fs.readFileSync(recordPath, "utf-8"));
    if (!rec.passed) {
        throw new Error(`compliance gate failed: passed=false (id=${rec.attestation_id})`);
    }
    if (rec.overall_score < minScore) {
        throw new Error(
            `compliance gate failed: score ${rec.overall_score} < ${minScore} (id=${rec.attestation_id})`,
        );
    }
    return rec;
});

export const attestationId = result.apply(r => r.attestation_id);
export const overallScore = result.apply(r => r.overall_score);
export const passed = result.apply(r => r.passed);
