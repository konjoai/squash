/**
 * Mock fixtures matching the squash demo server response shapes. Used when
 * the live server is unreachable so the dashboard always has a story to show.
 */
import type {
  ScanResult,
  InsurancePackage,
  ModelScan,
  Finding,
  Remediation,
  FrameworkScores,
} from "./types";

const MOCK_FINDINGS: Finding[] = [
  {
    code: "no-spdx",
    severity: "warn",
    title: "No SPDX SBOM emitted alongside attestation",
    framework: "EU AI Act",
    article: "Annex IV §2(c) · Article 11",
    citation_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
  },
  {
    code: "no-model-card",
    severity: "error",
    title: "Model card missing intended use & limitations",
    framework: "EU AI Act",
    article: "Annex IV §2(d)",
    citation_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
  },
  {
    code: "missing-data-governance",
    severity: "warn",
    title: "Training data governance evidence absent",
    framework: "NIST AI RMF",
    article: "GOVERN 1.4",
    citation_url: "https://www.nist.gov/itl/ai-risk-management-framework",
  },
  {
    code: "owasp-llm07-prompt-injection",
    severity: "info",
    title: "No mitigation declared for prompt injection vector",
    framework: "OWASP LLM",
    article: "LLM07:2025",
    citation_url: "https://genai.owasp.org/llm-top-10/",
  },
  {
    code: "missing-incident-plan",
    severity: "critical",
    title: "Post-market incident reporting plan not documented",
    framework: "EU AI Act",
    article: "Article 73",
    citation_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
  },
];

const MOCK_REMEDIATIONS: Remediation[] = [
  {
    severity: "warn",
    title: "No SPDX SBOM emitted alongside attestation",
    why: "EU AI Act Article 11 requires technical documentation including a software bill of materials (SBOM) in a machine-readable form.",
    how_to_fix: [
      "Add `cyclonedx-bom` to your project.",
      "Re-run `squash attest --emit-spdx`.",
      "Verify with `squash diff --against last-passing`.",
    ],
    framework: "EU AI Act",
    article: "Annex IV §2(c) · Article 11",
    citation_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
  },
  {
    severity: "error",
    title: "Model card missing intended use & limitations",
    why: "Annex IV §2(d) requires documented intended purpose, expected performance, and known limitations.",
    how_to_fix: [
      "Generate a draft model card with `squash card init`.",
      "Fill in the `intended_use` and `limitations` sections.",
      "Re-run `squash attest`.",
    ],
    framework: "EU AI Act",
    article: "Annex IV §2(d)",
    citation_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
  },
  {
    severity: "critical",
    title: "Post-market incident reporting plan not documented",
    why: "EU AI Act Article 73 requires providers of high-risk AI systems to report serious incidents to the relevant market surveillance authority.",
    how_to_fix: [
      "Adopt an incident response runbook (squash provides a template).",
      "Designate an accountable owner with a paging schedule.",
      "Re-attest with `--include incident-plan.md`.",
    ],
    framework: "EU AI Act",
    article: "Article 73",
    citation_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
  },
];

export const MOCK_MODEL_SCAN: ModelScan = {
  model: {
    name: "llama3.2:3b",
    size_bytes: 2_023_000_000,
    digest: "a80c4f17acd5",
    family: "llama",
  },
  attestation_id: "att_2026_05_06_llama3_2_3b",
  canonical_sha256: "a1b2c3d4e5f6789a012b34c56d78e90f12a3b4c5d6e7f8901a2b3c4d5e6f7890",
  cyclonedx_components: 87,
  file_count: 42,
  issued_at: "2026-05-06T00:00:00Z",
  score: 78,
  passed: false,
  findings: MOCK_FINDINGS,
  remediations: MOCK_REMEDIATIONS,
  elapsed_ms: 232.4,
  family: "llama",
};

export const MOCK_SCAN_RESULT: ScanResult = {
  ok: true,
  available: false,
  model_a: MOCK_MODEL_SCAN,
  model_b: {
    ...MOCK_MODEL_SCAN,
    model: { ...MOCK_MODEL_SCAN.model, name: "qwen2.5:7b", digest: "b91d4f28be17", family: "qwen" },
    attestation_id: "att_2026_05_06_qwen2_5_7b",
    score: 84,
    passed: true,
    findings: MOCK_FINDINGS.slice(0, 2),
    remediations: MOCK_REMEDIATIONS.slice(0, 1),
    family: "qwen",
  },
  verdict_winner: "qwen2.5:7b",
};

export const MOCK_INSURANCE: InsurancePackage = {
  org_name: "Acme AI Inc.",
  generated_at: "2026-05-06T00:00:00Z",
  aggregate_risk_score: 34,
  aggregate_compliance_score: 78,
  total_models: 8,
  high_risk_count: 1,
  medium_risk_count: 3,
  low_risk_count: 4,
  open_cves: 2,
  critical_cves: 0,
  recent_incidents: 0,
  underwriter_formats: {
    munich_re: {
      schema: "munich_re_ai_cyber_v1",
      ai_maturity_level: 3,
      coverage_recommendation: "ENHANCED",
      control_domains: {
        technical_security:     { rating: "Strong",   coverage_pct: 92, notes: "SBOM + signing in place" },
        operational_excellence: { rating: "Adequate", coverage_pct: 78, notes: "Drift monitoring partial" },
        ai_governance:          { rating: "Adequate", coverage_pct: 74, notes: "Model cards: 6 of 8" },
        data_quality_provenance:{ rating: "Strong",   coverage_pct: 88, notes: "Lineage tracked" },
        incident_resilience:    { rating: "Weak",     coverage_pct: 52, notes: "Plan drafts only" },
      },
    },
    coalition: {
      schema: "coalition_ai_risk_v1",
      aggregate_ai_risk_score: 34,
      risk_categories: {
        ai_model_security:    { score: 22, assessment: "Low risk" },
        ai_operational_risk:  { score: 38, assessment: "Moderate risk" },
        ai_governance:        { score: 28, assessment: "Low risk" },
        ai_incident_history:  { score:  6, assessment: "Minimal" },
        third_party_ai_risk:  { score: 41, assessment: "Moderate risk" },
      },
    },
    generic: {
      schema: "squash_insurance_generic_v1",
      risk_posture: {
        aggregate_risk_score_0_100: 34,
        aggregate_compliance_score_0_100: 78,
        risk_interpretation: "Acceptable — focus on incident plan and 2 medium-risk models.",
      },
    },
  },
};

export const MOCK_FRAMEWORK_SCORES: FrameworkScores = {
  eu_ai_act:   0.82,
  nist_ai_rmf: 0.74,
  owasp_llm:   0.91,
  iso_42001:   0.68,
};

/** Compute framework scores from a model scan's findings. Pure for testing. */
export function frameworkScoresFromScan(scan: ModelScan): FrameworkScores {
  const sevWeight: Record<string, number> = { info: 1, warn: 4, error: 12, critical: 30 };
  const buckets: Record<string, number> = {
    eu_ai_act: 0,
    nist_ai_rmf: 0,
    owasp_llm: 0,
    iso_42001: 0,
  };
  for (const f of scan.findings) {
    const w = sevWeight[f.severity] ?? 1;
    if (f.framework.startsWith("EU AI"))    buckets.eu_ai_act += w;
    else if (f.framework.startsWith("NIST"))buckets.nist_ai_rmf += w;
    else if (f.framework.startsWith("OWASP"))buckets.owasp_llm += w;
    else if (f.framework.startsWith("ISO")) buckets.iso_42001 += w;
  }
  // Convert demerit → score in [0, 1]. 100 demerit ≈ 0; 0 demerit = 1.
  const toScore = (d: number) => Math.max(0, Math.min(1, 1 - d / 100));
  return {
    eu_ai_act:   toScore(buckets.eu_ai_act),
    nist_ai_rmf: toScore(buckets.nist_ai_rmf),
    owasp_llm:   toScore(buckets.owasp_llm),
    iso_42001:   toScore(buckets.iso_42001),
  };
}
