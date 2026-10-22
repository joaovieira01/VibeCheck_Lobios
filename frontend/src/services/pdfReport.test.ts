import { describe, expect, it } from "vitest";
import { buildSecurityReport } from "./pdfReport";
import type { Analysis } from "../types";

const sample: Analysis = {
  id: "test-analysis",
  filename: "app.py",
  language: "Python",
  linesAnalyzed: 14,
  createdAt: "2025-01-10T12:00:00.000Z",
  durationMs: 12,
  rulesRun: 21,
  findings: [
    {
      id: "sql-injection",
      title: "Possível SQL Injection",
      severity: "Crítica",
      cwe: "CWE-89",
      owaspId: "A05",
      owaspName: "Injeção",
      description: "A consulta SQL mistura instruções com valores dinâmicos.",
      recommendation: "Use parâmetros vinculados em consultas.",
      impact: "Uma pessoa atacante pode ler ou modificar informações.",
      prevention: "Use consultas parametrizadas e teste entradas manipuladas.",
      locations: [4],
      evidence: ['query = f"SELECT * FROM users WHERE id = {user_id}"'],
    },
  ],
};

describe("buildSecurityReport", () => {
  it("creates a downloadable PDF with summary and finding detail pages", () => {
    const report = buildSecurityReport(sample);
    const bytes = new Uint8Array(report.output("arraybuffer"));
    const signature = new TextDecoder().decode(bytes.slice(0, 5));

    expect(signature).toBe("%PDF-");
    expect(bytes.byteLength).toBeGreaterThan(4_000);
    expect(report.getNumberOfPages()).toBeGreaterThanOrEqual(2);
  });

  it("creates a report when the scan has no findings", () => {
    const report = buildSecurityReport({ ...sample, findings: [] });

    expect(report.output("arraybuffer").byteLength).toBeGreaterThan(1_000);
  });
});
