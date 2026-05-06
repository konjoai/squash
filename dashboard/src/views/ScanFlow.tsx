import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { StagePipeline, ease } from "@konjoai/ui";
import type { Stage } from "@konjoai/ui";

export type ScanState = "idle" | "scanning" | "done" | "error";

export interface ScanFlowProps {
  state: ScanState;
  /** Called when the user presses Run Scan. */
  onRun: () => void;
  /** Optional override of the stage descriptors. */
  stages?: Stage[];
  /** Optional message shown next to the run button. */
  message?: string;
}

const SCAN_STAGES: { id: string; label: string; detail?: string }[] = [
  { id: "canonicalize", label: "Canonicalize", detail: "RFC 8785 JCS" },
  { id: "manifest",     label: "Manifest",     detail: "SHA-256 of files" },
  { id: "bom",          label: "SBOM",         detail: "CycloneDX" },
  { id: "policy",       label: "Policy",       detail: "EU AI Act · NIST · OWASP" },
  { id: "sign",         label: "Sign",         detail: "Ed25519" },
  { id: "verify",       label: "Verify",       detail: "Re-encode is byte-stable" },
];

/**
 * The animated scan pipeline. When the user kicks off a scan, stages walk
 * left-to-right; the Run button locks; on completion, the pipeline freezes
 * green and the parent reveals findings + certificate.
 *
 * Internally, the cadence is a 6-phase walk over ~3 seconds. The actual API
 * call resolves separately; visual progress is decoupled so the user gets
 * confidence-by-motion even on a fast/cached scan.
 */
export function ScanFlow({ state, onRun, message }: ScanFlowProps) {
  const [phase, setPhase] = useState<number>(SCAN_STAGES.length);

  useEffect(() => {
    if (state === "scanning") {
      setPhase(0);
      const id = setInterval(() => {
        setPhase((p) => {
          if (p < SCAN_STAGES.length - 1) return p + 1;
          clearInterval(id);
          return p;
        });
      }, 480);
      return () => clearInterval(id);
    }
    if (state === "done") {
      setPhase(SCAN_STAGES.length);
    }
    if (state === "idle") {
      setPhase(SCAN_STAGES.length);
    }
  }, [state]);

  const stages: Stage[] = SCAN_STAGES.map((s, i) => ({
    id: s.id,
    label: s.label,
    detail: s.detail,
    status:
      state === "idle"
        ? "pending"
        : state === "done"
        ? "done"
        : i < phase
        ? "done"
        : i === phase
        ? "active"
        : "pending",
    durationMs:
      state === "done" || (state === "scanning" && i < phase)
        ? Math.max(2, [4, 18, 42, 64, 22, 8][i] ?? 10)
        : undefined,
  }));

  const running = state === "scanning";

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-konjo-display text-konjo-fg" style={{ fontSize: 22, fontWeight: 600 }}>
            Compliance scan
          </h2>
          <p className="text-konjo-fg-muted text-[13px] mt-1">
            Canonicalize → Manifest → SBOM → Policy → Sign → Verify · all six steps reproducible from the same seed.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <AnimatePresence>
            {message && (
              <motion.span
                key={message}
                initial={{ opacity: 0, x: 8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -8 }}
                transition={{ duration: 0.4, ease: ease.kanjo }}
                className="text-konjo-mono text-[12px] text-konjo-fg-muted"
              >
                {message}
              </motion.span>
            )}
          </AnimatePresence>
          <button
            type="button"
            onClick={onRun}
            disabled={running}
            className={[
              "px-5 py-2.5 rounded-konjo border border-konjo-line text-konjo-mono uppercase tracking-[0.18em] text-[12px]",
              "transition-colors duration-150",
              running
                ? "bg-konjo-surface text-konjo-fg-muted cursor-progress"
                : "bg-konjo-accent text-konjo-bg hover:brightness-110 cursor-pointer shadow-konjo-glow",
            ].join(" ")}
          >
            {running ? "scanning…" : state === "done" ? "rescan" : "run scan"}
          </button>
        </div>
      </div>

      <div className="glass-konjo rounded-konjo-lg p-5">
        <StagePipeline stages={stages} />
      </div>
    </section>
  );
}
