import { motion } from "motion/react";
import { ease } from "@konjoai/ui";
import { REG_MILESTONES, daysUntil, fmtRelative } from "../lib/dates";

export interface RegulatoryTimelineProps {
  /** ms since epoch — caller can override for tests / fixed-clock screenshots. */
  now?: Date;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "var(--color-sev-critical)",
  error:    "var(--color-sev-error)",
  warn:     "var(--color-sev-warn)",
  info:     "var(--color-sev-info)",
};

/**
 * Horizontal regulatory timeline. Shows EU AI Act / ISO 42001 / Colorado /
 * NYC LL 144 milestones with severity-tinted markers and time-from-now.
 */
export function RegulatoryTimeline({ now = new Date() }: RegulatoryTimelineProps) {
  const items = REG_MILESTONES.map((m) => ({
    ...m,
    days: daysUntil(m.date, now),
    rel: fmtRelative(m.date, now),
  }));

  // Position each marker on a 0..1 axis spanning [today - 30d, max(milestone) + 30d].
  const minTs = -30;
  const maxTs = Math.max(...items.map((i) => i.days)) + 60;
  const span = maxTs - minTs;
  const xfor = (d: number) => ((d - minTs) / span) * 100;
  const todayPct = xfor(0);

  return (
    <section className="space-y-4">
      <div>
        <h2 className="text-konjo-display text-konjo-fg" style={{ fontSize: 22, fontWeight: 600 }}>
          Regulatory horizon
        </h2>
        <p className="text-konjo-fg-muted text-[13px] mt-1">
          Where every clock is ticking.
        </p>
      </div>

      <div className="glass-konjo rounded-konjo-lg p-6">
        <div className="relative h-32">
          {/* Axis */}
          <div
            className="absolute left-0 right-0"
            style={{
              top: "55%",
              height: 2,
              background: "var(--color-konjo-line)",
            }}
          />
          {/* Today marker */}
          <div
            className="absolute"
            style={{
              left: `${todayPct}%`,
              top: "30%",
              bottom: "30%",
              width: 2,
              background: "var(--color-konjo-accent)",
              boxShadow: "0 0 12px var(--color-konjo-accent)",
              transform: "translateX(-1px)",
            }}
            aria-hidden
          />
          <div
            className="absolute text-konjo-mono uppercase tracking-[0.18em] text-[10px] text-konjo-accent"
            style={{ left: `${todayPct}%`, bottom: 0, transform: "translateX(-50%)" }}
          >
            today
          </div>

          {/* Milestones */}
          {items.map((m, i) => {
            const c = SEVERITY_COLOR[m.severity] ?? SEVERITY_COLOR.info;
            const above = i % 2 === 0;
            return (
              <motion.div
                key={m.id}
                initial={{ opacity: 0, scale: 0.6 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.6, ease: ease.kanjo, delay: i * 0.07 }}
                className="absolute"
                style={{ left: `${xfor(m.days)}%`, top: 0, bottom: 0, width: 0 }}
              >
                <div
                  className="absolute rounded-full"
                  style={{
                    top: "55%",
                    left: 0,
                    width: 12, height: 12,
                    background: c,
                    boxShadow: `0 0 14px ${c}`,
                    transform: "translate(-6px, -6px)",
                  }}
                  aria-hidden
                />
                <div
                  className="absolute"
                  style={{
                    left: 0,
                    width: 1,
                    background: "var(--color-konjo-line)",
                    ...(above
                      ? { top: 0, height: "55%" }
                      : { top: "55%", height: "45%" }),
                  }}
                  aria-hidden
                />
                <div
                  className="absolute"
                  style={{
                    left: 0,
                    transform: "translateX(-50%)",
                    width: 180,
                    textAlign: "center",
                    ...(above ? { top: 0 } : { bottom: 0 }),
                  }}
                >
                  <div
                    className="text-konjo-mono uppercase tracking-[0.16em] tabular-nums text-[10px]"
                    style={{ color: c }}
                  >
                    {m.region}
                  </div>
                  <div className="text-konjo-fg text-[12px] mt-0.5 leading-tight">
                    {m.label}
                  </div>
                  <div className="text-konjo-mono text-[10px] text-konjo-fg-muted mt-0.5 tabular-nums">
                    {m.date} · {m.rel}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
