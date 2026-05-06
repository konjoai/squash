/**
 * Regulatory countdown helpers.
 *
 * The EU AI Act's GPAI obligations enter into application on 2026-08-02
 * (Article 113(b)). Other milestones are layered for the regulatory timeline.
 */

export const REG_MILESTONES = [
  { id: "eu-ai-act-gpai",  label: "EU AI Act · GPAI obligations", date: "2026-08-02", severity: "critical" as const, region: "EU" },
  { id: "iso-42001-mature",label: "ISO/IEC 42001 · maturity",     date: "2026-09-30", severity: "warn"     as const, region: "ISO" },
  { id: "co-ai-act",       label: "Colorado AI Act · in force",   date: "2026-10-01", severity: "warn"     as const, region: "US-CO" },
  { id: "nyc-ll-144",      label: "NYC Local Law 144 · audit",    date: "2026-11-01", severity: "info"     as const, region: "US-NY" },
  { id: "eu-ai-act-hr",    label: "EU AI Act · high-risk full",   date: "2027-08-02", severity: "info"     as const, region: "EU" },
];

/**
 * Days from `from` (default today) to a YYYY-MM-DD target. Negative if past.
 */
export function daysUntil(target: string, from: Date = new Date()): number {
  const t = new Date(target + "T00:00:00Z").getTime();
  const f = Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate());
  return Math.round((t - f) / (1000 * 60 * 60 * 24));
}

export function fmtRelative(target: string, from: Date = new Date()): string {
  const d = daysUntil(target, from);
  if (d < 0) return `${Math.abs(d)} days ago`;
  if (d === 0) return "today";
  if (d === 1) return "tomorrow";
  if (d < 60) return `in ${d} days`;
  if (d < 365) return `in ~${Math.round(d / 30)} months`;
  return `in ~${(d / 365).toFixed(1)} years`;
}

export function fmtBytes(b: number): string {
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(0)} KB`;
  return `${b} B`;
}
