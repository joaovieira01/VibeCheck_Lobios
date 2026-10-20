export interface Finding {
  id: string;
  title: string;
  severity: "Crítica" | "Alta" | "Média" | "Baixa";
  cwe: string;
  owaspId: string;
  owaspName: string;
  description: string;
  recommendation: string;
  impact: string;
  prevention: string;
  locations: number[];
  evidence: string[];
}

export interface Analysis {
  id: string;
  filename: string;
  language: string;
  linesAnalyzed: number;
  createdAt: string;
  durationMs: number;
  findings: Finding[];
  rulesRun: number;
}

export interface AnalysisInput {
  filename: string;
  source: string;
}

export interface AnalysisService {
  analyze(input: AnalysisInput): Promise<Analysis>;
  getHistory(): Promise<Analysis[]>;
  clearHistory(): Promise<void>;
}
