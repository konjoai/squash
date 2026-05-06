/**
 * TypeScript types mirroring the squash demo server response shapes.
 *
 * Source of truth lives in /Users/wesleyscholl/squash/squash/*.py — when those
 * shapes evolve, update here. We keep these intentionally narrow (only the
 * fields the dashboard reads).
 */

export type Severity = "info" | "warn" | "error" | "critical";

export type Framework =
  | "EU AI Act"
  | "NIST AI RMF"
  | "ISO 42001"
  | "OWASP LLM"
  | "SLSA";

export interface Finding {
  code: string;
  severity: Severity;
  title: string;
  framework: string;
  article: string;
  citation_url: string;
}

export interface Remediation {
  severity: Severity;
  title: string;
  why: string;
  how_to_fix: string[];
  framework: string;
  article: string;
  citation_url: string;
}

export interface ModelMeta {
  name: string;
  size_bytes: number;
  digest: string;
  family: string;
}

export interface ModelScan {
  model: ModelMeta;
  attestation_id: string;
  canonical_sha256?: string;
  cyclonedx_components: number;
  file_count: number;
  issued_at: string;
  score: number;
  passed: boolean | null;
  findings: Finding[];
  remediations: Remediation[];
  elapsed_ms: number;
  family: string;
}

export interface ScanResult {
  ok: boolean;
  available: boolean;
  model_a: ModelScan;
  model_b?: ModelScan;
  verdict_winner?: string;
}

export type UnderwriterFormat = "munich_re" | "coalition" | "generic";

export interface MunichRePackage {
  schema: "munich_re_ai_cyber_v1";
  ai_maturity_level: number;
  coverage_recommendation: "STANDARD" | "ENHANCED" | "SPECIALIST";
  control_domains: Record<string, {
    rating: string;
    coverage_pct: number;
    notes: string;
  }>;
}

export interface CoalitionPackage {
  schema: "coalition_ai_risk_v1";
  aggregate_ai_risk_score: number;
  risk_categories: Record<string, {
    score: number;
    assessment: string;
  }>;
}

export interface GenericPackage {
  schema: "squash_insurance_generic_v1";
  risk_posture: {
    aggregate_risk_score_0_100: number;
    aggregate_compliance_score_0_100: number;
    risk_interpretation: string;
  };
}

export interface InsurancePackage {
  org_name: string;
  generated_at: string;
  aggregate_risk_score: number;
  aggregate_compliance_score: number;
  total_models: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  open_cves: number;
  critical_cves: number;
  recent_incidents: number;
  underwriter_formats: {
    munich_re: MunichRePackage;
    coalition: CoalitionPackage;
    generic: GenericPackage;
  };
}

/**
 * Compliance score per framework — 0..1. Drives the tri-ring.
 */
export interface FrameworkScores {
  eu_ai_act: number;
  nist_ai_rmf: number;
  owasp_llm: number;
  iso_42001?: number;
}
