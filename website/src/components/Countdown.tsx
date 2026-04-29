"use client";

import { useEffect, useState } from "react";

const ENFORCEMENT_DATE = new Date("2026-08-02T00:00:00Z");

function getTimeLeft() {
  const now = new Date();
  const diff = ENFORCEMENT_DATE.getTime() - now.getTime();
  if (diff <= 0) return { days: 0, hours: 0, minutes: 0, seconds: 0 };
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((diff % (1000 * 60)) / 1000);
  return { days, hours, minutes, seconds };
}

export default function Countdown() {
  const [time, setTime] = useState(getTimeLeft());

  useEffect(() => {
    const timer = setInterval(() => setTime(getTimeLeft()), 1000);
    return () => clearInterval(timer);
  }, []);

  const pad = (n: number) => String(n).padStart(2, "0");

  return (
    <div className="inline-flex items-center gap-1 font-mono text-sm">
      <span className="text-red-400 font-bold">{time.days}d</span>
      <span className="text-slate-500">:</span>
      <span className="text-red-400 font-bold">{pad(time.hours)}h</span>
      <span className="text-slate-500">:</span>
      <span className="text-red-400 font-bold">{pad(time.minutes)}m</span>
      <span className="text-slate-500">:</span>
      <span className="text-red-400 font-bold">{pad(time.seconds)}s</span>
    </div>
  );
}
