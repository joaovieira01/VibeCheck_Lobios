import type { Analysis, AnalysisService, Finding } from "../types";
import { scanSource } from "./scanner";

const HISTORY_KEY = "vibecheck.frontend.history.v1";
const MAX_HISTORY = 20;
const MAX_SOURCE_BYTES = 1_000_000;

function isFinding(value: unknown): value is Finding {
  if (typeof value !== "object" || value === null) return false;
  const finding = value as Record<string, unknown>;
  return (
    typeof finding.id === "string" &&
    typeof finding.title === "string" &&
    ["Crítica", "Alta", "Média", "Baixa"].includes(String(finding.severity)) &&
    typeof finding.cwe === "string" &&
    typeof finding.owaspId === "string" &&
    typeof finding.owaspName === "string" &&
    typeof finding.description === "string" &&
    typeof finding.recommendation === "string" &&
    typeof finding.impact === "string" &&
    typeof finding.prevention === "string" &&
    Array.isArray(finding.locations) &&
    finding.locations.every((location) => Number.isInteger(location) && location > 0) &&
    Array.isArray(finding.evidence) &&
    finding.evidence.every((entry) => typeof entry === "string")
  );
}

function isAnalysis(value: unknown): value is Analysis {
  if (typeof value !== "object" || value === null) return false;
  const analysis = value as Record<string, unknown>;
  return (
    typeof analysis.id === "string" &&
    typeof analysis.filename === "string" &&
    typeof analysis.language === "string" &&
    Number.isInteger(analysis.linesAnalyzed) &&
    typeof analysis.createdAt === "string" &&
    Number.isFinite(analysis.durationMs) &&
    Number.isInteger(analysis.rulesRun) &&
    Array.isArray(analysis.findings) &&
    analysis.findings.every(isFinding)
  );
}

function readHistory(): Analysis[] {
  try {
    const stored = localStorage.getItem(HISTORY_KEY);
    if (!stored) return [];
    const history: unknown = JSON.parse(stored);
    if (!Array.isArray(history) || !history.every(isAnalysis)) {
      throw new Error(
        "O histórico local está em formato inválido. Limpe os dados do navegador para continuar.",
      );
    }
    return history;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error("O histórico local está corrompido. Limpe os dados do navegador para continuar.");
    }
    throw error;
  }
}

function detectLanguage(filename: string): string {
  const extension = filename.split(".").pop()?.toLowerCase();
  const languages: Record<string, string> = {
    py: "Python",
    js: "JavaScript",
    jsx: "JavaScript / React",
    ts: "TypeScript",
    tsx: "TypeScript / React",
    json: "JSON",
    txt: "Texto / dependências",
    php: "PHP",
    java: "Java",
    go: "Go",
    rb: "Ruby",
    cs: "C#",
    c: "C",
    cpp: "C++",
  };
  return extension ? languages[extension] ?? extension.toUpperCase() : "Texto";
}

export class LocalAnalysisService implements AnalysisService {
  async analyze(input: { filename: string; source: string }): Promise<Analysis> {
    const size = new Blob([input.source]).size;
    if (size > MAX_SOURCE_BYTES) {
      throw new Error("O código excede o limite de 1 MB.");
    }
    if (!input.source.trim()) {
      throw new Error("Envie um arquivo ou cole um trecho de código para analisar.");
    }

    const start = performance.now();
    const result = scanSource(input.source, input.filename);
    const analysis: Analysis = {
      id: crypto.randomUUID(),
      filename: input.filename,
      language: detectLanguage(input.filename),
      linesAnalyzed: input.source.split(/\r?\n/).length,
      createdAt: new Date().toISOString(),
      durationMs: Math.round(performance.now() - start),
      findings: result.findings,
      rulesRun: result.rulesRun,
    };

    const history = readHistory();
    try {
      localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify([analysis, ...history].slice(0, MAX_HISTORY)),
      );
    } catch (error) {
      throw new Error(
        error instanceof Error
          ? `A análise foi executada, mas não foi possível salvar o histórico local: ${error.message}`
          : "A análise foi executada, mas não foi possível salvar o histórico local.",
      );
    }

    return analysis;
  }

  async getHistory(): Promise<Analysis[]> {
    return readHistory();
  }

  async clearHistory(): Promise<void> {
    localStorage.removeItem(HISTORY_KEY);
  }
}

export const analysisService: AnalysisService = new LocalAnalysisService();
