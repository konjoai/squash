import { useMemo } from "react";
import { motion } from "motion/react";
import { ease } from "@konjoai/ui";
import type { ModelScan } from "../lib/types";
import { fmtBytes } from "../lib/dates";

export interface CertificateBadgeProps {
  scan: ModelScan;
  /** When true, renders a wider full certificate; otherwise, a compact square badge. */
  full?: boolean;
}

function shortHash(h: string | undefined, n = 12): string {
  if (!h) return "—";
  if (h.length <= n) return h;
  return h.slice(0, n);
}

/**
 * SVG-rendered "Squash Verified" badge. Inline-sized so it can be downloaded
 * as-is or screenshot for marketing decks. The compact form is ~280px square;
 * the full form is a 720×260 horizontal certificate.
 */
export function CertificateBadge({ scan, full = false }: CertificateBadgeProps) {
  const score = scan.score;
  const passed = scan.passed === true;
  const accent = passed ? "var(--color-konjo-good)" : "var(--color-konjo-warm)";
  const ts = scan.issued_at.replace("T", " ").replace("Z", " UTC");

  const svg = useMemo(() => {
    if (full) {
      return (
        <svg viewBox="0 0 720 260" width="100%" style={{ maxWidth: 720 }} aria-label="squash certificate">
          <defs>
            <linearGradient id="cert-bg" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%"   stopColor="#11141c" />
              <stop offset="100%" stopColor="#181c27" />
            </linearGradient>
            <linearGradient id="cert-stroke" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%"   stopColor="var(--color-konjo-violet)" stopOpacity="0.7" />
              <stop offset="100%" stopColor={accent} stopOpacity="0.4" />
            </linearGradient>
          </defs>
          <rect x="2" y="2" width="716" height="256" rx="14" fill="url(#cert-bg)" stroke="url(#cert-stroke)" strokeWidth="1.5" />
          {/* Wordmark */}
          <text x="32" y="46" fill="#e7ecf4" style={{ fontFamily: "JetBrains Mono, ui-monospace", fontSize: 13, letterSpacing: "0.32em", textTransform: "uppercase", fontWeight: 600 }}>
            squash
          </text>
          <circle cx="105" cy="42" r="3" fill="var(--color-konjo-accent)" />
          <text x="32" y="92" fill="#e7ecf4" style={{ fontFamily: "Inter, ui-sans-serif", fontSize: 28, fontWeight: 600, letterSpacing: "-0.02em" }}>
            Compliance Certificate
          </text>
          <text x="32" y="116" fill="#8a93a8" style={{ fontFamily: "Inter, ui-sans-serif", fontSize: 13 }}>
            EU AI Act · NIST AI RMF · OWASP LLM · ISO 42001
          </text>

          {/* Model strip */}
          <text x="32" y="166" fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase" }}>
            model
          </text>
          <text x="32" y="186" fill="#e7ecf4" style={{ fontFamily: "JetBrains Mono", fontSize: 14 }}>
            {scan.model.name}
          </text>
          <text x="32" y="206" fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 11 }}>
            {fmtBytes(scan.model.size_bytes)} · {scan.cyclonedx_components} components · {scan.file_count} files
          </text>

          {/* Hash strip */}
          <text x="240" y="166" fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase" }}>
            attestation
          </text>
          <text x="240" y="186" fill="#e7ecf4" style={{ fontFamily: "JetBrains Mono", fontSize: 11 }}>
            {scan.attestation_id}
          </text>
          <text x="240" y="206" fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 11 }}>
            sha256: {shortHash(scan.canonical_sha256, 24)}
          </text>

          {/* Score circle */}
          <g transform="translate(580, 130)">
            <circle r="64" fill="none" stroke="#232838" strokeWidth="6" />
            <circle r="64" fill="none" stroke={accent} strokeWidth="6" strokeLinecap="round"
              strokeDasharray={`${(2 * Math.PI * 64) * (score / 100)} ${2 * Math.PI * 64}`}
              transform="rotate(-90)" />
            <text textAnchor="middle" y={-2} fill="#e7ecf4" style={{ fontFamily: "Inter", fontSize: 38, fontWeight: 700 }}>
              {score}
            </text>
            <text textAnchor="middle" y={20} fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase" }}>
              {passed ? "passed" : "review"}
            </text>
          </g>

          {/* Footer */}
          <text x="32" y="240" fill="#4a5063" style={{ fontFamily: "JetBrains Mono", fontSize: 10 }}>
            issued {ts} · ed25519 + RFC 3161 · verifiable at getsquash.dev/verify
          </text>
        </svg>
      );
    }
    return (
      <svg viewBox="0 0 280 280" width="100%" style={{ maxWidth: 280 }} aria-label="squash badge">
        <defs>
          <linearGradient id="badge-bg" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%"   stopColor="#11141c" />
            <stop offset="100%" stopColor="#181c27" />
          </linearGradient>
        </defs>
        <rect x="2" y="2" width="276" height="276" rx="16" fill="url(#badge-bg)" stroke={accent} strokeOpacity="0.5" strokeWidth="1.5" />
        <text x="140" y="40" textAnchor="middle" fill="#e7ecf4" style={{ fontFamily: "JetBrains Mono", fontSize: 11, letterSpacing: "0.32em", textTransform: "uppercase", fontWeight: 600 }}>
          squash
        </text>
        <circle cx="200" cy="36" r="2.5" fill="var(--color-konjo-accent)" />
        <text x="140" y="74" textAnchor="middle" fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 9, letterSpacing: "0.18em", textTransform: "uppercase" }}>
          {passed ? "verified" : "review pending"}
        </text>

        <g transform="translate(140, 150)">
          <circle r="68" fill="none" stroke="#232838" strokeWidth="5" />
          <circle r="68" fill="none" stroke={accent} strokeWidth="5" strokeLinecap="round"
            strokeDasharray={`${(2 * Math.PI * 68) * (score / 100)} ${2 * Math.PI * 68}`}
            transform="rotate(-90)" />
          <text textAnchor="middle" y={-4} fill="#e7ecf4" style={{ fontFamily: "Inter", fontSize: 44, fontWeight: 700 }}>
            {score}
          </text>
          <text textAnchor="middle" y={22} fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 9, letterSpacing: "0.18em", textTransform: "uppercase" }}>
            score
          </text>
        </g>

        <text x="140" y="252" textAnchor="middle" fill="#8a93a8" style={{ fontFamily: "JetBrains Mono", fontSize: 9 }}>
          {scan.model.name}
        </text>
        <text x="140" y="266" textAnchor="middle" fill="#4a5063" style={{ fontFamily: "JetBrains Mono", fontSize: 8 }}>
          {scan.attestation_id}
        </text>
      </svg>
    );
  }, [scan, score, passed, accent, ts, full]);

  function downloadSvg() {
    const wrapper = document.createElement("div");
    wrapper.innerHTML = (document.getElementById("cert-svg-host")?.innerHTML) ?? "";
    const svgEl = wrapper.querySelector("svg");
    if (!svgEl) return;
    const xml = new XMLSerializer().serializeToString(svgEl);
    const blob = new Blob([xml], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `squash-${scan.model.name.replaceAll(":", "-")}-${scan.attestation_id}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="space-y-4">
      <div className="flex items-baseline justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-konjo-display text-konjo-fg" style={{ fontSize: 22, fontWeight: 600 }}>
            Verifiable badge
          </h2>
          <p className="text-konjo-fg-muted text-[13px] mt-1">
            Ed25519-signed certificate · embed in README, vendor pack, or marketing.
          </p>
        </div>
        <button
          type="button"
          onClick={downloadSvg}
          className="px-4 py-2 rounded-konjo border border-konjo-line bg-konjo-surface text-konjo-fg text-konjo-mono uppercase tracking-[0.16em] text-[11px] hover:bg-konjo-surface-2 transition-colors"
        >
          download .svg
        </button>
      </div>
      <motion.div
        id="cert-svg-host"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: ease.kanjo }}
        className="glass-konjo rounded-konjo-lg p-6 flex justify-center"
      >
        {svg}
      </motion.div>
    </section>
  );
}
