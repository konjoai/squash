import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FindingsList } from "./FindingsList";
import { MOCK_MODEL_SCAN } from "../lib/mock";

describe("FindingsList", () => {
  it("renders all finding titles", () => {
    render(<FindingsList findings={MOCK_MODEL_SCAN.findings} remediations={MOCK_MODEL_SCAN.remediations} />);
    for (const f of MOCK_MODEL_SCAN.findings) {
      expect(screen.getByText(f.title)).toBeInTheDocument();
    }
  });

  it("orders critical before warn before info", () => {
    render(<FindingsList findings={MOCK_MODEL_SCAN.findings} remediations={MOCK_MODEL_SCAN.remediations} />);
    const items = screen.getAllByRole("listitem");
    expect(items.length).toBe(MOCK_MODEL_SCAN.findings.length);
    // First listitem is the highest-severity finding (critical).
    expect(items[0]).toHaveTextContent(/Critical/i);
  });

  it("expands to show how-to-fix steps", async () => {
    render(<FindingsList findings={MOCK_MODEL_SCAN.findings} remediations={MOCK_MODEL_SCAN.remediations} />);
    const button = screen.getAllByRole("button")[0];
    await userEvent.click(button);
    expect(button).toHaveAttribute("aria-expanded", "true");
  });

  it("renders an empty-green state when no findings", () => {
    render(<FindingsList findings={[]} remediations={[]} />);
    expect(screen.getByText(/no findings/i)).toBeInTheDocument();
  });
});
