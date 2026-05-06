import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ExecutiveSummary } from "./ExecutiveSummary";
import { MOCK_FRAMEWORK_SCORES, MOCK_MODEL_SCAN } from "../lib/mock";

describe("ExecutiveSummary", () => {
  it("renders the tri-ring with model name as subtitle", () => {
    render(
      <ExecutiveSummary
        scores={MOCK_FRAMEWORK_SCORES}
        scan={MOCK_MODEL_SCAN}
      />,
    );
    expect(screen.getByText(MOCK_MODEL_SCAN.model.name)).toBeInTheDocument();
  });

  it("shows the EU AI Act day-count pill (also appears in RiskRing legend)", () => {
    render(<ExecutiveSummary scores={MOCK_FRAMEWORK_SCORES} scan={MOCK_MODEL_SCAN} />);
    // EU AI Act appears twice: once in the pill label, once in the RiskRing legend.
    expect(screen.getAllByText("EU AI Act").length).toBeGreaterThanOrEqual(2);
  });

  it("counts critical+error findings in the Findings pill", () => {
    render(<ExecutiveSummary scores={MOCK_FRAMEWORK_SCORES} scan={MOCK_MODEL_SCAN} />);
    const expected = MOCK_MODEL_SCAN.findings.filter(
      (f) => f.severity === "critical" || f.severity === "error",
    ).length;
    // The pill renders the value as a big number — find by content.
    expect(screen.getByText(`${expected}`)).toBeInTheDocument();
  });

  it("insurance pill flips Pending → Ready when insuranceReady=true", () => {
    const { rerender } = render(
      <ExecutiveSummary scores={MOCK_FRAMEWORK_SCORES} scan={MOCK_MODEL_SCAN} insuranceReady={false} />,
    );
    expect(screen.getByText("Pending")).toBeInTheDocument();
    rerender(
      <ExecutiveSummary scores={MOCK_FRAMEWORK_SCORES} scan={MOCK_MODEL_SCAN} insuranceReady={true} />,
    );
    expect(screen.getByText("Ready")).toBeInTheDocument();
  });
});
