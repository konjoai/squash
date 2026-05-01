"use client";

import { useState } from "react";

interface FAQItem {
  q: string;
  a: string;
}

export default function FAQAccordion({ items }: { items: FAQItem[] }) {
  const [open, setOpen] = useState<number | null>(null);

  return (
    <div className="space-y-3">
      {items.map((item, i) => (
        <div
          key={i}
          className={`border rounded-xl overflow-hidden transition-colors duration-200 ${
            open === i ? "border-[#22c55e]/40 bg-[#0a1a10]" : "border-[#1a2540] bg-[#0d1421] hover:border-[#1f3a28]"
          }`}
        >
          <button
            onClick={() => setOpen(open === i ? null : i)}
            className="w-full text-left p-6 flex items-start justify-between gap-4 group"
          >
            <span className="font-bold text-[#f1f5f9] text-base leading-snug">{item.q}</span>
            <span
              className={`text-[#22c55e] font-mono text-xl leading-none shrink-0 transition-transform duration-300 ${
                open === i ? "rotate-45" : ""
              }`}
            >
              +
            </span>
          </button>
          <div
            className={`grid transition-all duration-300 ease-in-out ${
              open === i ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
            }`}
          >
            <div className="overflow-hidden">
              <p className="text-[#94a3b8] text-sm leading-relaxed px-6 pb-6">{item.a}</p>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
