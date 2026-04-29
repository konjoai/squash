import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Squash — Squash violations, not velocity.",
  description:
    "Automated EU AI Act compliance for ML teams. Annex IV documentation in 10 seconds. CI/CD-native, open-core, developer-first.",
  keywords: [
    "EU AI Act compliance",
    "Annex IV documentation",
    "AI governance",
    "ML compliance automation",
    "NIST AI RMF",
    "SBOM",
    "CycloneDX",
    "SLSA",
  ],
  openGraph: {
    title: "Squash — Squash violations, not velocity.",
    description:
      "EU AI Act enforcement is August 2, 2026. Squash automates Annex IV compliance for ML teams. Ships in CI/CD in 10 seconds.",
    url: "https://getsquash.dev",
    siteName: "Squash",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Squash — Squash violations, not velocity.",
    description: "EU AI Act enforcement: August 2, 2026. Automate Annex IV compliance in 10 seconds.",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
