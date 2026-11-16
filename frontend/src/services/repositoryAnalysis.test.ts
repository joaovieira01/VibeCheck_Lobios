import { describe, expect, it } from "vitest";
import type { Finding } from "../types";
import { aggregateRepositoryFindings } from "./repositoryAnalysis";

function finding(
  id: string,
  severity: Finding["severity"],
  owaspId: string,
  owaspName: string,
  locations: number[],
): Finding {
  return {
    id,
    title: `Regra ${id}`,
    severity,
    cwe: "CWE-89",
    owaspId,
    owaspName,
    description: "Descrição do risco.",
    recommendation: "Corrija a entrada.",
    impact: "Impacto de teste.",
    prevention: "Valide a entrada.",
    locations,
    evidence: locations.map((line) => `linha ${line}`),
  };
}

describe("aggregateRepositoryFindings", () => {
  it("soma ocorrências por severidade e OWASP e ordena arquivos", () => {
    const summary = aggregateRepositoryFindings({
      "z/server.ts": [
        finding("sql-injection", "Crítica", "A05", "Injeção", [4, 9]),
      ],
      "a/auth.py": [
        finding("debug-mode", "Alta", "A02", "Configuração insegura", [3]),
        finding("debug-mode", "Alta", "A02", "Configuração insegura", [7, 8]),
      ],
    });

    expect(summary.bySeverity).toEqual({
      "Crítica": 2,
      Alta: 3,
      "Média": 0,
      Baixa: 0,
    });
    expect(summary.byOwasp).toEqual({
      "A05 - Injeção": 2,
      "A02 - Configuração insegura": 3,
    });
    expect(summary.files.map((file) => file.path)).toEqual([
      "a/auth.py",
      "z/server.ts",
    ]);
    expect(summary.totalFindings).toBe(3);
    expect(summary.totalOccurrences).toBe(5);
  });

  it("devolve resumo vazio sem erros quando não há achados", () => {
    expect(aggregateRepositoryFindings({})).toEqual({
      bySeverity: { "Crítica": 0, Alta: 0, "Média": 0, Baixa: 0 },
      byOwasp: {},
      files: [],
      totalFindings: 0,
      totalOccurrences: 0,
    });
  });
});
