import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Dial, ease } from "@konjoai/ui";
import type { Severity } from "@konjoai/ui";
import type { InsurancePackage, UnderwriterFormat } from "../lib/types";

export interface InsurancePreviewProps {
  pkg: InsurancePackage;
}

const FORMATS: { id: UnderwriterFormat; label: string; carrier: string }[] = [
  { id: "munich_re", label: "Munich Re",  carrier: "munich_re_ai_cyber_v1" },
  { id: "coalition", label: "Coalition",  carrier: "coalition_ai_risk_v1" },
  { id: "generic",   label: "Generic",    carrier: "squash_insurance_generic_v1" },
];

function ratingSeverity(rating: string): Severity {
  if (rating === "Strong") return "ok";
  if (rating === "Adequate") return "info";
  if (rating === "Weak") return "warn";
  return "high";
}

function MunichReView({ pkg }: { pkg: InsurancePackage }) {
  const m = pkg.underwriter_formats.munich_re;
  return (
    <div className="grid md:grid-cols-[auto_1fr] gap-6 items-start">
      <div className="flex flex-col items-center gap-4">
        <Dial
          value={m.ai_maturity_level}
          min={0}
          max={4}
          unit="/4"
          size={170}
          label="Maturity"
          severity={m.ai_maturity_level >= 3 ? "ok" : m.ai_maturity_level >= 2 ? "info" : "warn"}
          format={(v) => v.toFixed(0)}
        />
        <div
          className="text-konjo-mono uppercase tracking-[0.16em] text-[11px] text-konjo-violet text-center"
          style={{ minWidth: 170 }}
        >
          {m.coverage_recommendation}
        </div>
      </div>

      <div className="space-y-2">
        <div className="text-konjo-mono text-[10px] uppercase tracking-[0.18em] text-konjo-fg-muted mb-2">
          Control domains
        </div>
        {Object.entries(m.control_domains).map(([k, v]) => {
          const sev = ratingSeverity(v.rating);
          const c =
            sev === "ok"   ? "var(--color-konjo-good)" :
            sev === "info" ? "var(--color-konjo-cool)" :
            sev === "warn" ? "var(--color-konjo-warm)" : "var(--color-konjo-hot)";
          return (
            <div key={k} className="flex items-center gap-3">
              <div className="text-konjo-mono text-[12px] text-konjo-fg-muted" style={{ minWidth: 200 }}>
                {k.replaceAll("_", " ")}
              </div>
              <div className="flex-1 h-2 rounded-full bg-konjo-line/60 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${v.coverage_pct}%` }}
                  transition={{ duration: 0.8, ease: ease.kanjo }}
                  className="h-full"
                  style={{ background: c, boxShadow: `0 0 8px ${c}` }}
                />
              </div>
              <div className="text-konjo-mono text-[11px] tabular-nums" style={{ color: c, minWidth: 60 }}>
                {v.coverage_pct}% · {v.rating}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CoalitionView({ pkg }: { pkg: InsurancePackage }) {
  const c = pkg.underwriter_formats.coalition;
  const sev: Severity = c.aggregate_ai_risk_score < 25 ? "ok" : c.aggregate_ai_risk_score < 50 ? "info" : c.aggregate_ai_risk_score < 75 ? "warn" : "high";
  return (
    <div className="grid md:grid-cols-[auto_1fr] gap-6 items-start">
      <Dial
        value={c.aggregate_ai_risk_score}
        min={0}
        max={100}
        size={170}
        label="AI risk"
        unit="/100"
        severity={sev}
        sublabel="lower is better"
      />
      <div className="space-y-3">
        <div className="text-konjo-mono text-[10px] uppercase tracking-[0.18em] text-konjo-fg-muted">
          Risk categories
        </div>
        {Object.entries(c.risk_categories).map(([k, v]) => (
          <div key={k} className="flex items-center justify-between gap-3 py-1 border-b border-konjo-line/50 last:border-b-0">
            <span className="text-konjo-mono text-[12px] text-konjo-fg-muted">
              {k.replaceAll("_", " ")}
            </span>
            <span className="text-konjo-mono text-[12px] tabular-nums text-konjo-fg">
              {v.score} · <span className="text-konjo-fg-muted">{v.assessment}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function GenericView({ pkg }: { pkg: InsurancePackage }) {
  const g = pkg.underwriter_formats.generic;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: "Risk score",       value: g.risk_posture.aggregate_risk_score_0_100 },
          { label: "Compliance score", value: g.risk_posture.aggregate_compliance_score_0_100 },
          { label: "Open CVEs",        value: pkg.open_cves },
          { label: "Critical CVEs",    value: pkg.critical_cves },
        ].map((item) => (
          <div key={item.label} className="glass-konjo rounded-konjo p-3">
            <div className="text-konjo-mono text-[10px] uppercase tracking-[0.18em] text-konjo-fg-muted">
              {item.label}
            </div>
            <div
              className="text-konjo-display text-konjo-fg leading-none mt-1 tabular-nums"
              style={{ fontSize: 28, fontWeight: 600 }}
            >
              {item.value}
            </div>
          </div>
        ))}
      </div>
      <div className="text-konjo-mono text-[12px] text-konjo-fg-muted">
        {g.risk_posture.risk_interpretation}
      </div>
    </div>
  );
}

export function InsurancePreview({ pkg }: InsurancePreviewProps) {
  const [active, setActive] = useState<UnderwriterFormat>("munich_re");

  return (
    <section className="space-y-4">
      <div className="flex items-baseline justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-konjo-display text-konjo-fg" style={{ fontSize: 22, fontWeight: 600 }}>
            Insurance package
          </h2>
          <p className="text-konjo-fg-muted text-[13px] mt-1">
            Underwriter-ready risk profile across {pkg.total_models} models · {pkg.org_name}
          </p>
        </div>
        <div className="inline-flex items-center gap-1 p-1 rounded-konjo bg-konjo-surface border border-konjo-line">
          {FORMATS.map((f) => {
            const isActive = active === f.id;
            return (
              <button
                key={f.id}
                type="button"
                onClick={() => setActive(f.id)}
                className={[
                  "px-3 py-1.5 rounded-konjo-sm text-konjo-mono uppercase tracking-[0.16em] text-[11px] transition-colors",
                  isActive
                    ? "bg-konjo-accent text-konjo-bg"
                    : "text-konjo-fg-muted hover:text-konjo-fg",
                ].join(" ")}
                aria-pressed={isActive}
              >
                {f.label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="glass-konjo rounded-konjo-lg p-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={active}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.25, ease: ease.kanjo }}
          >
            {active === "munich_re" && <MunichReView pkg={pkg} />}
            {active === "coalition" && <CoalitionView pkg={pkg} />}
            {active === "generic"   && <GenericView   pkg={pkg} />}
          </motion.div>
        </AnimatePresence>
      </div>
    </section>
  );
}
