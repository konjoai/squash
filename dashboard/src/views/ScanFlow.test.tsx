import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScanFlow } from "./ScanFlow";

describe("ScanFlow", () => {
  it("idle: button reads 'run scan' and is enabled", () => {
    const onRun = vi.fn();
    render(<ScanFlow state="idle" onRun={onRun} />);
    const btn = screen.getByRole("button", { name: /run scan/i });
    expect(btn).toBeEnabled();
  });

  it("scanning: button locks and reads 'scanning…'", () => {
    render(<ScanFlow state="scanning" onRun={() => {}} />);
    const btn = screen.getByRole("button", { name: /scanning/i });
    expect(btn).toBeDisabled();
  });

  it("done: button reads 'rescan'", () => {
    render(<ScanFlow state="done" onRun={() => {}} />);
    expect(screen.getByRole("button", { name: /rescan/i })).toBeInTheDocument();
  });

  it("clicking the run button triggers onRun", async () => {
    const onRun = vi.fn();
    render(<ScanFlow state="idle" onRun={onRun} />);
    await userEvent.click(screen.getByRole("button", { name: /run scan/i }));
    expect(onRun).toHaveBeenCalledOnce();
  });

  it("renders all six scan stages", () => {
    render(<ScanFlow state="done" onRun={() => {}} />);
    for (const label of ["Canonicalize", "Manifest", "SBOM", "Policy", "Sign", "Verify"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });
});
