"use client";

import { useState } from "react";

interface IntegrationBlock {
  label: string;
  lang: string;
  code: string;
}

function TerminalDots() {
  return (
    <>
      <div className="terminal-dot bg-red-500 opacity-80" />
      <div className="terminal-dot bg-yellow-500 opacity-80" />
      <div className="terminal-dot bg-green-500 opacity-80" />
    </>
  );
}

export default function IntegrationTabs({ blocks }: { blocks: IntegrationBlock[] }) {
  const [active, setActive] = useState(0);

  return (
    <div>
      {/* Tab bar */}
      <div className="flex flex-wrap gap-2 mb-4">
        {blocks.map((b, i) => (
          <button
            key={b.label}
            onClick={() => setActive(i)}
            className={`px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all duration-200 ${
              active === i
                ? "bg-[#22c55e] text-white shadow-[0_0_12px_rgba(34,197,94,0.3)]"
                : "bg-[#0d1421] border border-[#1a2540] text-[#94a3b8] hover:border-[#22c55e]/40 hover:text-white"
            }`}
          >
            {b.label}
          </button>
        ))}
      </div>

      {/* Code panel */}
      <div className="terminal terminal-hero">
        <div className="terminal-header">
          <TerminalDots />
          <span className="text-[#475569] text-xs ml-2 font-mono">{blocks[active].label}</span>
        </div>
        <pre className="p-5 text-sm text-[#94a3b8] overflow-x-auto whitespace-pre font-mono leading-relaxed min-h-[160px]">
          {/* Simple syntax highlighting: commands in green, comments grey */}
          {blocks[active].code.split("\n").map((line, i) => {
            const isComment = line.trim().startsWith("#") || line.trim().startsWith("//");
            const isKey = /^[a-zA-Z_-]+:/.test(line.trim());
            return (
              <span
                key={i}
                className={
                  isComment ? "text-[#475569]" :
                  isKey ? "text-[#7dd3fc]" :
                  "text-[#94a3b8]"
                }
              >
                {line}
                {"\n"}
              </span>
            );
          })}
        </pre>
      </div>
    </div>
  );
}
