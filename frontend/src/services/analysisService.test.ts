import { afterEach, describe, expect, it, vi } from "vitest";
import type { Analysis } from "../types";
import { LocalAnalysisService } from "./analysisService";

const legacyAnalysis: Analysis = {
  id: "legacy-analysis",
  filename: "app.py",
  language: "Python",
  linesAnalyzed: 1,
  createdAt: "2025-01-10T12:00:00.000Z",
  durationMs: 1,
  rulesRun: 1,
  findings: [
    {
      id: "debug-mode",
      title: "Modo debug habilitado",
      severity: "Alta",
      cwe: "CWE-489",
      owaspId: "A02",
      owaspName: "Configuração insegura",
      description: "Descrição",
      recommendation: "Recomendação",
      impact: "Impacto",
      prevention: "Prevenção",
      locations: [1],
      evidence: ["DEBUG = True"],
    },
  ],
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("LocalAnalysisService", () => {
  it("continua lendo histórico sem o campo suggestedFix", async () => {
    vi.stubGlobal("localStorage", {
      getItem: () => JSON.stringify([legacyAnalysis]),
    });

    await expect(new LocalAnalysisService().getHistory()).resolves.toEqual([
      legacyAnalysis,
    ]);
  });

  it("valida sugestões salvas com uma correção por localização", async () => {
    const analysis = structuredClone(legacyAnalysis);
    analysis.findings[0].suggestedFix = [
      {
        before: "DEBUG = True",
        after: "DEBUG = False",
        explanation: "Desative debug.",
      },
    ];
    vi.stubGlobal("localStorage", {
      getItem: () => JSON.stringify([analysis]),
    });

    await expect(new LocalAnalysisService().getHistory()).resolves.toEqual([
      analysis,
    ]);
  });
});
