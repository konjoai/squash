"use client";

import { useEffect, useState, useRef } from "react";

interface TypingTerminalProps {
  lines: string[];
  title?: string;
  speed?: number;        // ms per character
  lineDelay?: number;    // ms between lines
  className?: string;
}

export default function TypingTerminal({
  lines,
  title,
  speed = 18,
  lineDelay = 120,
  className = "",
}: TypingTerminalProps) {
  const [displayedLines, setDisplayedLines] = useState<string[]>([]);
  const [currentLine, setCurrentLine] = useState(0);
  const [currentChar, setCurrentChar] = useState(0);
  const [done, setDone] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const [started, setStarted] = useState(false);

  // Start when scrolled into view
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) { setStarted(true); obs.disconnect(); } },
      { threshold: 0.3 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  useEffect(() => {
    if (!started || done) return;
    if (currentLine >= lines.length) { setDone(true); return; }

    const line = lines[currentLine];

    if (currentChar < line.length) {
      const t = setTimeout(() => {
        setDisplayedLines((prev) => {
          const updated = [...prev];
          updated[currentLine] = (updated[currentLine] ?? "") + line[currentChar];
          return updated;
        });
        setCurrentChar((c) => c + 1);
      }, speed);
      return () => clearTimeout(t);
    } else {
      const t = setTimeout(() => {
        setCurrentLine((l) => l + 1);
        setCurrentChar(0);
      }, lineDelay);
      return () => clearTimeout(t);
    }
  }, [started, currentLine, currentChar, lines, speed, lineDelay, done]);

  return (
    <div ref={ref} className={`terminal terminal-hero glow-green ${className}`}>
      <div className="terminal-header">
        <div className="terminal-dot bg-red-500 opacity-80" />
        <div className="terminal-dot bg-yellow-500 opacity-80" />
        <div className="terminal-dot bg-green-500 opacity-80" />
        {title && (
          <span className="text-[#475569] text-xs ml-2 font-mono truncate">{title}</span>
        )}
      </div>
      <pre className="p-6 text-xs leading-relaxed text-[#94a3b8] overflow-x-auto whitespace-pre font-mono min-h-[200px]">
        {displayedLines.map((line, i) => (
          <span key={i}>
            {line}
            {i === currentLine && !done && (
              <span className="cursor-blink" />
            )}
            {"\n"}
          </span>
        ))}
        {done && <span className="cursor-blink" />}
      </pre>
    </div>
  );
}
