import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ease } from "@konjoai/ui";
import type { Finding, Remediation, Severity } from "../lib/types";

export interface FindingsListProps {
  findings: Finding[];
  remediations: Remediation[];
  /** Stagger reveal — true after a fresh scan, false on initial load. */
  cinematic?: boolean;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4, error: 3, warn: 2, info: 1,
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--color-sev-critical)",
  error:    "var(--color-sev-error)",
  warn:     "var(--color-sev-warn)",
  info:     "var(--color-sev-info)",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical", error: "Error", warn: "Warn", info: "Info",
};

function FindingCard({
  finding,
  remediation,
  index,
  cinematic,
}: {
  finding: Finding;
  remediation?: Remediation;
  index: number;
  cinematic: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const c = SEVERITY_COLOR[finding.severity];

  return (
    <motion.li
      layout
      initial={cinematic ? { opacity: 0, y: 12, filter: "blur(6px)" } : false}
      animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      transition={{
        duration: 0.5,
        ease: ease.kanjo,
        delay: cinematic ? Math.min(index * 0.07, 0.7) : 0,
      }}
      className="glass-konjo rounded-konjo overflow-hidden border-l-2"
      style={{ borderLeftColor: c, boxShadow: `inset 1px 0 0 ${c}` }}
    >
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        className="w-full text-left px-4 py-3 flex items-start gap-3 hover:bg-konjo-surface-2/40 transition-colors"
        aria-expanded={expanded}
      >
        <span
          aria-hidden
          className="inline-block rounded-full mt-1.5 shrink-0"
          style={{ width: 8, height: 8, background: c, boxShadow: `0 0 10px ${c}` }}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-2 flex-wrap">
            <span
              className="text-konjo-mono text-[10px] uppercase tracking-[0.18em] tabular-nums"
              style={{ color: c }}
            >
              {SEVERITY_LABEL[finding.severity]}
            </span>
            <span className="text-konjo-fg-faint">·</span>
            <span className="text-konjo-mono text-[11px] text-konjo-fg-muted">
              {finding.framework}
            </span>
            <span className="text-konjo-fg-faint">·</span>
            <span className="text-konjo-mono text-[11px] text-konjo-fg-muted">
              {finding.article}
            </span>
          </div>
          <div className="text-konjo-fg mt-1" style={{ fontSize: 14 }}>
            {finding.title}
          </div>
        </div>
        <span
          className="text-konjo-fg-muted shrink-0 transition-transform"
          style={{ transform: expanded ? "rotate(90deg)" : "rotate(0deg)" }}
          aria-hidden
        >
          ›
        </span>
      </button>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28, ease: ease.kanjo }}
            className="overflow-hidden border-t border-konjo-line"
          >
            <div className="px-4 py-4 space-y-3">
              {remediation && (
                <>
                  <div>
                    <div className="text-konjo-mono text-[10px] uppercase tracking-[0.18em] text-konjo-fg-muted mb-1">
                      Why
                    </div>
                    <p className="text-konjo-fg-muted" style={{ fontSize: 13, lineHeight: 1.55 }}>
                      {remediation.why}
                    </p>
                  </div>
                  <div>
                    <div className="text-konjo-mono text-[10px] uppercase tracking-[0.18em] text-konjo-fg-muted mb-1">
                      How to fix
                    </div>
                    <ol className="space-y-1.5">
                      {remediation.how_to_fix.map((step, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span
                            className="text-konjo-mono text-[10px] tabular-nums shrink-0 mt-0.5"
                            style={{ color: c, minWidth: 14 }}
                          >
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <span className="text-konjo-mono text-konjo-fg" style={{ fontSize: 12 }}>
                            {step}
                          </span>
                        </li>
                      ))}
                    </ol>
                  </div>
                </>
              )}
              <div className="pt-1">
                <a
                  href={finding.citation_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-konjo-mono text-[11px] text-konjo-accent hover:underline"
                >
                  {finding.citation_url} ↗
                </a>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.li>
  );
}

export function FindingsList({ findings, remediations, cinematic = false }: FindingsListProps) {
  // Group findings by severity rank, descending.
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
  );
  const remByTitle = new Map(remediations.map((r) => [r.title, r]));

  if (sorted.length === 0) {
    return (
      <div className="glass-konjo rounded-konjo p-6 text-center">
        <div className="text-konjo-good text-konjo-display" style={{ fontSize: 16 }}>
          No findings — green across the board.
        </div>
        <p className="text-konjo-fg-muted text-[13px] mt-1">
          All applicable controls satisfied for this scan.
        </p>
      </div>
    );
  }

  return (
    <ul className="space-y-2">
      {sorted.map((f, i) => (
        <FindingCard
          key={f.code + i}
          finding={f}
          remediation={remByTitle.get(f.title)}
          index={i}
          cinematic={cinematic}
        />
      ))}
    </ul>
  );
}
