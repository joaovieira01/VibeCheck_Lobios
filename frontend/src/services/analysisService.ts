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

const API_URL = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "");
const TOKEN_KEY = "vibecheck.api.token.v1";
const LOCAL_USERS_KEY = "vibecheck.local.users.v1";

function readLocalUsers(): Record<string, string> {
  try {
    const stored = localStorage.getItem(LOCAL_USERS_KEY);
    if (!stored) return {};
    const parsed = JSON.parse(stored) as unknown;
    if (typeof parsed !== "object" || parsed === null) return {};
    return Object.fromEntries(
      Object.entries(parsed as Record<string, unknown>).filter(
        ([, value]) => typeof value === "string",
      ) as [string, string][],
    );
  } catch {
    return {};
  }
}

function writeLocalUsers(users: Record<string, string>): void {
  localStorage.setItem(LOCAL_USERS_KEY, JSON.stringify(users));
}

export function getApiToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

async function authenticateLocally(
  mode: "login" | "signup",
  email: string,
  password: string,
): Promise<void> {
  const normalized = email.trim();
  if (!normalized || !password.trim()) {
    throw new Error("Informe um e-mail e uma senha válidos.");
  }
  const users = readLocalUsers();
  if (mode === "signup") {
    users[normalized.toLowerCase()] = password;
    writeLocalUsers(users);
  } else if (!users[normalized.toLowerCase()]) {
    throw new Error("Conta não encontrada no modo local. Crie uma conta primeiro.");
  } else if (users[normalized.toLowerCase()] !== password) {
    throw new Error("Senha incorreta para este usuário local.");
  }
  localStorage.setItem(TOKEN_KEY, `local-demo-token:${normalized.toLowerCase()}`);
}

export async function authenticateWithApi(
  mode: "login" | "signup",
  email: string,
  password: string,
): Promise<void> {
  if (!API_URL) {
    await authenticateLocally(mode, email, password);
    return;
  }
  const response = await fetch(`${API_URL}/api/auth/${mode === "signup" ? "register" : "login"}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(typeof payload.detail === "string" ? payload.detail : "Não foi possível autenticar.");
  }
  if (typeof payload.token !== "string") {
    throw new Error("A API respondeu sem token de sessão.");
  }
  localStorage.setItem(TOKEN_KEY, payload.token);
}

export function logoutFromApi(): void {
  const token = getApiToken();
  if (API_URL && token) {
    void fetch(`${API_URL}/api/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => undefined);
  }
  localStorage.removeItem(TOKEN_KEY);
}

class ApiAnalysisService implements AnalysisService {
  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const token = getApiToken();
    if (!token) throw new Error("Sua sessão não está conectada à API. Entre novamente.");
    const response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        ...(init.headers ?? {}),
      },
    });
    if (response.status === 204) return undefined as T;
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) {
        localStorage.removeItem(TOKEN_KEY);
        throw new Error("Sessão expirada. Entre novamente.");
      }
      throw new Error(typeof payload.detail === "string" ? payload.detail : "Falha ao comunicar com a API.");
    }
    return payload as T;
  }

  analyze(input: { filename: string; source: string }): Promise<Analysis> {
    return this.request<Analysis>("/api/analyses", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  getHistory(): Promise<Analysis[]> {
    return this.request<Analysis[]>("/api/analyses");
  }

  clearHistory(): Promise<void> {
    return this.request<void>("/api/analyses", { method: "DELETE" });
  }
}

export const analysisService: AnalysisService =
  API_URL ? new ApiAnalysisService() : new LocalAnalysisService();
