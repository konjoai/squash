import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { RegulatoryTimeline } from "./RegulatoryTimeline";

describe("RegulatoryTimeline", () => {
  it("renders the 'today' marker label", () => {
    render(<RegulatoryTimeline now={new Date("2026-05-06T00:00:00Z")} />);
    expect(screen.getByText("today")).toBeInTheDocument();
  });

  it("renders all five regulatory milestones", () => {
    render(<RegulatoryTimeline now={new Date("2026-05-06T00:00:00Z")} />);
    expect(screen.getByText(/EU AI Act · GPAI/i)).toBeInTheDocument();
    expect(screen.getByText(/ISO\/IEC 42001/i)).toBeInTheDocument();
    expect(screen.getByText(/Colorado/i)).toBeInTheDocument();
    expect(screen.getByText(/NYC Local Law 144/i)).toBeInTheDocument();
    expect(screen.getByText(/EU AI Act · high-risk/i)).toBeInTheDocument();
  });
});
