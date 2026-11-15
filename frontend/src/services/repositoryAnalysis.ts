import type { Finding, RepositoryAnalysis } from "../types";

export interface RepositoryAnalysisSummary {
  bySeverity: Record<Finding["severity"], number>;
  byOwasp: Record<string, number>;
  files: Array<{
    path: string;
    findings: Finding[];
    occurrences: number;
  }>;
  totalFindings: number;
  totalOccurrences: number;
}

export function aggregateRepositoryFindings(
  findingsByFile: RepositoryAnalysis["findingsByFile"],
): RepositoryAnalysisSummary {
  const bySeverity: RepositoryAnalysisSummary["bySeverity"] = {
    "Crítica": 0,
    Alta: 0,
    "Média": 0,
    Baixa: 0,
  };
  const byOwasp: Record<string, number> = {};
  const files = Object.entries(findingsByFile)
    .map(([path, findings]) => {
      let occurrences = 0;
      for (const finding of findings) {
        const count = finding.locations.length;
        occurrences += count;
        bySeverity[finding.severity] += count;
        const category = `${finding.owaspId} - ${finding.owaspName}`;
        byOwasp[category] = (byOwasp[category] ?? 0) + count;
      }
      return { path, findings, occurrences };
    })
    .filter((file) => file.findings.length > 0)
    .sort((left, right) => left.path.localeCompare(right.path, "pt-BR"));

  const totalOccurrences = Object.values(bySeverity).reduce(
    (total, count) => total + count,
    0,
  );
  return {
    bySeverity,
    byOwasp,
    files,
    totalFindings: files.reduce((total, file) => total + file.findings.length, 0),
    totalOccurrences,
  };
}
