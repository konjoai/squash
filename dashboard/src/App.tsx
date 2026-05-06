import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { KonjoApp, ease } from "@konjoai/ui";
import { ExecutiveSummary } from "./views/ExecutiveSummary";
import { ScanFlow } from "./views/ScanFlow";
import { FindingsList } from "./views/FindingsList";
import { InsurancePreview } from "./views/InsurancePreview";
import { RegulatoryTimeline } from "./views/RegulatoryTimeline";
import { CertificateBadge } from "./views/CertificateBadge";
import type { ScanState } from "./views/ScanFlow";
import { ollamaScan } from "./lib/api";
import { MOCK_INSURANCE, frameworkScoresFromScan } from "./lib/mock";
import type { ModelScan, FrameworkScores } from "./lib/types";

const SCAN_VISUAL_MS = 480 * 6 + 250; // sync with ScanFlow's 6 stages × 480ms

export default function App() {
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [scan, setScan] = useState<ModelScan | undefined>();
  const [scores, setScores] = useState<FrameworkScores>({
    eu_ai_act: 0, nist_ai_rmf: 0, owasp_llm: 0, iso_42001: 0,
  });
  const [fromMock, setFromMock] = useState<boolean | null>(null);
  const [scanMessage, setScanMessage] = useState<string | undefined>();

  const runScan = async () => {
    setScanState("scanning");
    setScanMessage(undefined);
    const startedAt = Date.now();

    const result = await ollamaScan();

    const elapsed = Date.now() - startedAt;
    if (elapsed < SCAN_VISUAL_MS) {
      await new Promise((r) => setTimeout(r, SCAN_VISUAL_MS - elapsed));
    }

    if (result.ok) {
      const winner = result.data.verdict_winner;
      const chosen =
        winner && result.data.model_b && result.data.model_b.model.name === winner
          ? result.data.model_b
          : result.data.model_a;
      setScan(chosen);
      setScores(frameworkScoresFromScan(chosen));
      setFromMock(!!result.fromMock);
      setScanMessage(
        result.fromMock
          ? "ran on offline mock fixtures (no live server)"
          : `${chosen.model.name} · ${chosen.elapsed_ms.toFixed(0)} ms`,
      );
      setScanState("done");
    } else {
      setScanState("error");
      setScanMessage(result.error);
    }
  };

  useEffect(() => {
    void runScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const insuranceReady = scanState === "done";

  return (
    <KonjoApp
      product="squash"
      tagline="The Compliance Bridge"
      status={
        scanState === "scanning"
          ? { label: "scanning", severity: "info" }
          : scanState === "done"
          ? { label: fromMock ? "offline · mocks" : "live", severity: fromMock ? "warn" : "ok" }
          : { label: "idle", severity: "info" }
      }
    >
      <Hero />

      <div className="space-y-12 mt-10">
        <ExecutiveSummary scores={scores} scan={scan} insuranceReady={insuranceReady} />

        <ScanFlow
          state={scanState}
          onRun={() => { void runScan(); }}
          message={scanMessage}
        />

        <AnimatePresence mode="wait">
          {scan && scanState === "done" && (
            <motion.div
              key={scan.attestation_id}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: ease.kanjo }}
              className="space-y-12"
            >
              <section>
                <header className="mb-4">
                  <h2 className="text-konjo-display text-konjo-fg" style={{ fontSize: 22, fontWeight: 600 }}>
                    Findings
                  </h2>
                  <p className="text-konjo-fg-muted text-[13px] mt-1">
                    {scan.findings.length} signal{scan.findings.length === 1 ? "" : "s"} · sorted by severity · click any row to inspect remediation.
                  </p>
                </header>
                <FindingsList findings={scan.findings} remediations={scan.remediations} cinematic />
              </section>

              <CertificateBadge scan={scan} full />

              <InsurancePreview pkg={MOCK_INSURANCE} />
            </motion.div>
          )}
        </AnimatePresence>

        <RegulatoryTimeline />

        <Footer />
      </div>
    </KonjoApp>
  );
}

function Hero() {
  return (
    <section className="text-center pt-6 pb-2">
      <p className="text-konjo-mono uppercase tracking-[0.32em] text-konjo-violet" style={{ fontSize: 11 }}>
        the pytest of AI compliance
      </p>
      <h1
        className="text-konjo-display text-konjo-fg mt-4 mx-auto"
        style={{ fontSize: 52, fontWeight: 600, letterSpacing: "-0.025em", maxWidth: 920, lineHeight: 1.05 }}
      >
        Compliance you can <span style={{ color: "var(--color-konjo-violet)" }}>verify</span>,{" "}
        <span style={{ color: "var(--color-konjo-accent)" }}>sign</span>, and{" "}
        <span style={{ color: "var(--color-konjo-good)" }}>ship</span>.
      </h1>
      <p
        className="text-konjo-fg-muted mt-5 mx-auto"
        style={{ fontSize: 16, maxWidth: 640, lineHeight: 1.55 }}
      >
        Scan any model, generate Annex IV documentation, sign with Ed25519, and walk into your audit with receipts.
      </p>
    </section>
  );
}

function Footer() {
  return (
    <footer
      className="mt-12 pt-8 border-t border-konjo-line/60 text-konjo-fg-muted text-konjo-mono"
      style={{ fontSize: 12 }}
    >
      <div className="flex flex-wrap gap-4 justify-between items-baseline">
        <span>
          built on{" "}
          <span className="text-konjo-fg">@konjoai/ui</span>
          {" · "}
          <span className="text-konjo-fg">/api/ollama-scan</span>
          {" · "}
          <span className="text-konjo-fg">/api/attest</span>
        </span>
        <span className="text-konjo-fg-faint">
          part of the KonjoAI portfolio · vectro · squish · kyro · miru · kohaku · kairu · toki
        </span>
      </div>
    </footer>
  );
}
