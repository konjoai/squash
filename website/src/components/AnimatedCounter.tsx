"use client";

import { useEffect, useRef, useState } from "react";

interface AnimatedCounterProps {
  value: string;       // e.g. "78%", "$67.4B", "€15M"
  duration?: number;   // ms
  className?: string;
}

function parseNumber(v: string): { prefix: string; num: number; suffix: string } | null {
  const m = v.match(/^([^0-9]*)([0-9]+(?:\.[0-9]+)?)(.*)$/);
  if (!m) return null;
  return { prefix: m[1], num: parseFloat(m[2]), suffix: m[3] };
}

export default function AnimatedCounter({ value, duration = 1600, className = "" }: AnimatedCounterProps) {
  const ref = useRef<HTMLSpanElement>(null);
  const [display, setDisplay] = useState(value);
  const [triggered, setTriggered] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) { setTriggered(true); obs.disconnect(); } },
      { threshold: 0.5 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  useEffect(() => {
    if (!triggered) return;
    const parsed = parseNumber(value);
    if (!parsed) return;

    const { prefix, num, suffix } = parsed;
    const isInt = Number.isInteger(num);
    const decimals = isInt ? 0 : (value.split(".")[1]?.replace(/[^0-9]/g, "").length ?? 1);
    const start = Date.now();

    const tick = () => {
      const elapsed = Date.now() - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = num * eased;
      setDisplay(`${prefix}${current.toFixed(decimals)}${suffix}`);
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [triggered, value, duration]);

  return <span ref={ref} className={className}>{display}</span>;
}
