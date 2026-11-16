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
  suggestedFix?: SuggestedFix[];
}

export interface SuggestedFix {
  before: string;
  after: string;
  explanation: string;
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

export interface RepositoryAnalysis {
  id: string;
  analysisType: "repository";
  filename: string;
  createdAt: string;
  findingsByFile: Record<string, Finding[]>;
  countsBySeverity: Partial<Record<Finding["severity"], number>>;
  countsByOwasp: Record<string, number>;
  filesAnalyzed: string[];
  ignoredFiles: Array<{ path: string; reason: string }>;
  filesNotAnalyzed: string[];
  partial: boolean;
  durationSeconds: number;
  findingsTruncated: boolean;
  truncatedFindingsCount: number;
  truncatedOccurrencesCount: number;
  pathsTruncated: boolean;
}

export interface RepositoryAnalysisHistoryItem {
  id: string;
  filename: string;
  createdAt: string;
  countsBySeverity: Partial<Record<Finding["severity"], number>>;
  countsByOwasp: Record<string, number>;
  filesAnalyzedCount: number;
  partial: boolean;
  durationSeconds: number;
  findingsTruncated: boolean;
  truncatedFindingsCount: number;
  truncatedOccurrencesCount: number;
}

export interface RepositoryAnalysisService {
  analyzeRepository(file: File): Promise<RepositoryAnalysis>;
  getRepositoryHistory(): Promise<RepositoryAnalysisHistoryItem[]>;
  getRepositoryAnalysis(id: string): Promise<RepositoryAnalysis>;
}
