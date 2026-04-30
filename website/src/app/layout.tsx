import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://squash.works"),
  title: "Squash — Squash violations, not velocity.",
  description:
    "Automated EU AI Act compliance for ML teams. Annex IV documentation in 10 seconds. CI/CD-native, open-core, developer-first. Up to €35M in fines for non-compliance — enforcement starts August 2, 2026.",
  keywords: [
    "EU AI Act compliance",
    "Annex IV documentation",
    "AI governance",
    "ML compliance automation",
    "NIST AI RMF",
    "ISO 42001",
    "SBOM",
    "ML-BOM",
    "CycloneDX",
    "SPDX",
    "SLSA provenance",
    "AI risk management",
    "CISO AI compliance",
    "squash-ai",
    "AI Act enforcement",
  ],
  openGraph: {
    title: "Squash — Squash violations, not velocity.",
    description:
      "EU AI Act enforcement is August 2, 2026. Up to €35M for non-compliance. Squash automates Annex IV, ML-BOM, SBOM, and policy gating for ML teams — in 10 seconds, inside your CI pipeline.",
    url: "https://squash.works",
    siteName: "Squash",
    type: "website",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: "Squash — Squash violations, not velocity.",
    description:
      "EU AI Act enforcement: August 2, 2026. €35M fines. Automate Annex IV compliance in 10 seconds with squash-ai. Open-core, CI-native, developer-first.",
    creator: "@squash_works",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
    },
  },
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="antialiased">{children}</body>
    </html>
  );
}
