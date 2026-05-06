import { describe, it, expect } from "vitest";
import { daysUntil, fmtRelative, fmtBytes, REG_MILESTONES } from "./dates";

describe("daysUntil", () => {
  it("returns 0 for the same UTC day", () => {
    const today = new Date("2026-05-06T15:00:00Z");
    expect(daysUntil("2026-05-06", today)).toBe(0);
  });

  it("returns positive for future dates", () => {
    const today = new Date("2026-05-06T00:00:00Z");
    expect(daysUntil("2026-08-02", today)).toBe(88);
  });

  it("returns negative for past dates", () => {
    const today = new Date("2026-05-06T00:00:00Z");
    expect(daysUntil("2026-05-01", today)).toBe(-5);
  });
});

describe("fmtRelative", () => {
  const today = new Date("2026-05-06T00:00:00Z");
  it("today / tomorrow / past", () => {
    expect(fmtRelative("2026-05-06", today)).toBe("today");
    expect(fmtRelative("2026-05-07", today)).toBe("tomorrow");
    expect(fmtRelative("2026-05-05", today)).toBe("1 days ago");
  });
  it("near future uses 'in N days'", () => {
    expect(fmtRelative("2026-05-20", today)).toBe("in 14 days");
  });
  it("medium future uses 'in ~N months'", () => {
    expect(fmtRelative("2026-08-02", today)).toBe("in ~3 months");
  });
});

describe("fmtBytes", () => {
  it("formats by magnitude", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(900)).toBe("900 B");
    expect(fmtBytes(1500)).toBe("2 KB");
    expect(fmtBytes(2_500_000)).toBe("2.5 MB");
    expect(fmtBytes(2_023_000_000)).toBe("2.02 GB");
  });
});

describe("REG_MILESTONES", () => {
  it("starts with the EU AI Act enforcement date", () => {
    expect(REG_MILESTONES[0].id).toBe("eu-ai-act-gpai");
    expect(REG_MILESTONES[0].date).toBe("2026-08-02");
    expect(REG_MILESTONES[0].severity).toBe("critical");
  });
  it("milestones are chronologically ordered", () => {
    const dates = REG_MILESTONES.map((m) => new Date(m.date).getTime());
    for (let i = 1; i < dates.length; i++) {
      expect(dates[i]).toBeGreaterThan(dates[i - 1]);
    }
  });
});
