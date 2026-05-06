import { describe, it, expect } from "vitest";
import {
  MOCK_MODEL_SCAN,
  MOCK_SCAN_RESULT,
  MOCK_INSURANCE,
  frameworkScoresFromScan,
} from "./mock";

describe("mock fixtures", () => {
  it("MOCK_MODEL_SCAN has at least one finding per major framework", () => {
    const fr = new Set(MOCK_MODEL_SCAN.findings.map((f) => f.framework));
    expect(fr.has("EU AI Act")).toBe(true);
    expect(fr.has("NIST AI RMF")).toBe(true);
    expect(fr.has("OWASP LLM")).toBe(true);
  });

  it("MOCK_SCAN_RESULT verdict_winner exists in model_a or model_b", () => {
    const r = MOCK_SCAN_RESULT;
    const names = [r.model_a.model.name, r.model_b?.model.name].filter(Boolean);
    expect(names).toContain(r.verdict_winner);
  });

  it("MOCK_INSURANCE preserves underwriter format invariants", () => {
    const m = MOCK_INSURANCE.underwriter_formats.munich_re;
    expect(["STANDARD", "ENHANCED", "SPECIALIST"]).toContain(m.coverage_recommendation);
    expect(m.ai_maturity_level).toBeGreaterThanOrEqual(1);
    expect(m.ai_maturity_level).toBeLessThanOrEqual(4);
  });
});

describe("frameworkScoresFromScan", () => {
  it("returns 1.0 for an empty findings list", () => {
    const s = frameworkScoresFromScan({ ...MOCK_MODEL_SCAN, findings: [] });
    expect(s.eu_ai_act).toBe(1);
    expect(s.nist_ai_rmf).toBe(1);
    expect(s.owasp_llm).toBe(1);
  });

  it("a critical EU AI Act finding tanks only that framework", () => {
    const s = frameworkScoresFromScan({
      ...MOCK_MODEL_SCAN,
      findings: [{
        code: "x", severity: "critical", title: "t",
        framework: "EU AI Act", article: "x", citation_url: "",
      }],
    });
    expect(s.eu_ai_act).toBeLessThan(s.nist_ai_rmf);
    expect(s.nist_ai_rmf).toBe(1);
    expect(s.owasp_llm).toBe(1);
  });

  it("scores are clamped to [0, 1]", () => {
    const findings = Array.from({ length: 20 }).map(() => ({
      code: "x", severity: "critical" as const, title: "t",
      framework: "EU AI Act", article: "x", citation_url: "",
    }));
    const s = frameworkScoresFromScan({ ...MOCK_MODEL_SCAN, findings });
    expect(s.eu_ai_act).toBe(0);
  });
});
