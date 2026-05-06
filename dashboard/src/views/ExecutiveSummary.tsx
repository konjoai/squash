import { motion } from "motion/react";
import { RiskRing, Dial, ease } from "@konjoai/ui";
import type { Severity } from "@konjoai/ui";
import { daysUntil, fmtRelative, REG_MILESTONES } from "../lib/dates";
import type { FrameworkScores, ModelScan } from "../lib/types";

export interface ExecutiveSummaryProps {
  scores: FrameworkScores;
  /** Currently selected model — used for sublabel context. */
  scan?: ModelScan;
  /** Insurance package readiness — drives the bottom pill. */
  insuranceReady?: boolean;
}

function ringSeverity(score: number): Severity {
  if (score >= 0.85) return "ok";
  if (score >= 0.65) return "info";
  if (score >= 0.45) return "warn";
  return "high";
}

function Pill({
  label,
  value,
  severity,
  caption,
}: {
  label: string;
  value: string;
  severity: Severity;
  caption?: string;
}) {
  const colorMap: Record<Severity, string> = {
    ok:       "var(--color-konjo-good)",
    info:     "var(--color-konjo-cool)",
    warn:     "var(--color-konjo-warm)",
    high:     "var(--color-konjo-hot)",
    critical: "var(--color-konjo-hot)",
  };
  const c = colorMap[severity];
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: ease.kanjo }}
      className="glass-konjo rounded-konjo p-4 flex items-baseline gap-3 min-w-0"
    >
      <span
        className="inline-block rounded-full shrink-0"
        style={{
          width: 8, height: 8, background: c,
          boxShadow: `0 0 10px ${c}`,
          alignSelf: "center",
        }}
      />
      <div className="min-w-0">
        <div className="text-konjo-mono text-[10px] uppercase tracking-[0.18em] text-konjo-fg-muted">
          {label}
        </div>
        <div
          className="text-konjo-display text-konjo-fg leading-tight tabular-nums"
          style={{ fontSize: 22, fontWeight: 600, color: c }}
        >
          {value}
        </div>
        {caption && (
          <div className="text-konjo-mono text-[11px] text-konjo-fg-muted mt-0.5 truncate">
            {caption}
          </div>
        )}
      </div>
    </motion.div>
  );
}

/**
 * The executive view — first thing a CISO or auditor sees.
 *
 * Layout: tri-ring (left) + four pills (right).
 *   - Days to EU AI Act enforcement
 *   - Active critical findings
 *   - Models in portfolio
 *   - Insurance package readiness
 */
export function ExecutiveSummary({ scores, scan, insuranceReady }: ExecutiveSummaryProps) {
  const days = daysUntil(REG_MILESTONES[0].date);
  const criticalCount = scan?.findings.filter((f) => f.severity === "critical" || f.severity === "error").length ?? 0;

  // Headline = mean of all framework scores (if iso defined), else 3-frame mean.
  const all = [scores.eu_ai_act, scores.nist_ai_rmf, scores.owasp_llm];
  if (scores.iso_42001 != null) all.push(scores.iso_42001);
  const headline = all.reduce((a, b) => a + b, 0) / all.length;

  const daySeverity: Severity = days < 30 ? "high" : days < 60 ? "warn" : "info";

  return (
    <section className="grid lg:grid-cols-[auto_1fr] gap-8 items-center">
      <div className="flex justify-center lg:justify-start">
        <RiskRing
          size={320}
          title="Compliance"
          subtitle={scan?.model.name ?? "no scan yet"}
          rings={[
            { label: "Headline",      value: headline,           severity: ringSeverity(headline) },
            { label: "EU AI Act",     value: scores.eu_ai_act,   severity: ringSeverity(scores.eu_ai_act) },
            { label: "NIST AI RMF",   value: scores.nist_ai_rmf, severity: ringSeverity(scores.nist_ai_rmf) },
            { label: "OWASP LLM",     value: scores.owasp_llm,   severity: ringSeverity(scores.owasp_llm) },
          ]}
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-2 gap-3 max-w-xl">
        <Pill
          label="EU AI Act"
          value={`${days}d`}
          severity={daySeverity}
          caption={`${fmtRelative(REG_MILESTONES[0].date)}`}
        />
        <Pill
          label="Findings"
          value={`${criticalCount}`}
          severity={criticalCount > 0 ? "high" : "ok"}
          caption={criticalCount > 0 ? "critical or error" : "no blockers"}
        />
        <Pill
          label="Score"
          value={`${Math.round(headline * 100)}`}
          severity={ringSeverity(headline)}
          caption="weighted across frameworks"
        />
        <Pill
          label="Insurance"
          value={insuranceReady ? "Ready" : "Pending"}
          severity={insuranceReady ? "ok" : "warn"}
          caption={insuranceReady ? "Munich Re · Coalition · Generic" : "run a scan first"}
        />
      </div>

      {/* Hidden Dial export so future surfaces (e.g. throughput, latency) can still reach for the primitive without a new import. */}
      <noscript>
        <Dial value={0} hideValue size={1} />
      </noscript>
    </section>
  );
}
