import { AlertTriangle, Archive, FileCode2, LoaderCircle, Upload } from "lucide-react";
import { useMemo, useState, type ChangeEvent, type FormEvent } from "react";
import { FindingFix } from "./FindingFix";
import type {
  Finding,
  RepositoryAnalysis,
  RepositoryAnalysisService,
} from "../types";
import { aggregateRepositoryFindings } from "../services/repositoryAnalysis";

const severityOrder: Finding["severity"][] = ["Crítica", "Alta", "Média", "Baixa"];

function severityClass(severity: Finding["severity"]): string {
  if (severity === "Crítica") return "critical";
  if (severity === "Alta") return "high";
  if (severity === "Média") return "medium";
  return "low";
}

export function RepositoryTab({
  apiEnabled,
  service,
}: {
  apiEnabled: boolean;
  service: RepositoryAnalysisService;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<RepositoryAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const summary = useMemo(
    () => aggregateRepositoryFindings(analysis?.findingsByFile ?? {}),
    [analysis],
  );
  const displayedSeverityCounts = analysis?.findingsTruncated
    ? { ...summary.bySeverity, ...analysis.countsBySeverity }
    : summary.bySeverity;
  const displayedOwaspCounts = analysis?.findingsTruncated
    ? analysis.countsByOwasp
    : summary.byOwasp;
  const displayedOccurrenceCount = Object.values(displayedSeverityCounts).reduce(
    (total, count) => total + count,
    0,
  );

  function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const nextFile = event.target.files?.[0] ?? null;
    event.target.value = "";
    setError("");
    setAnalysis(null);
    if (!nextFile) {
      setFile(null);
      return;
    }
    if (!nextFile.name.toLowerCase().endsWith(".zip")) {
      setFile(null);
      setError("Selecione um arquivo com extensão .zip.");
      return;
    }
    if (nextFile.size > 25_000_000) {
      setFile(null);
      setError("O arquivo ZIP deve ter no máximo 25 MB.");
      return;
    }
    setFile(nextFile);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!apiEnabled) {
      setError("A análise de repositório exige a API do VibeCheck configurada.");
      return;
    }
    if (!file) {
      setError("Escolha um arquivo .zip para começar.");
      return;
    }

    setLoading(true);
    setError("");
    try {
      setAnalysis(await service.analyzeRepository(file));
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Não foi possível analisar o repositório.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="workspace-card repository-section">
      <header className="repository-heading">
        <div>
          <div className="eyebrow">ANÁLISE DE REPOSITÓRIO</div>
          <h2>Revise um projeto inteiro</h2>
          <p>Envie um arquivo ZIP. O conteúdo é analisado no backend e o resultado fica no seu histórico.</p>
        </div>
        <span className="repository-heading-icon"><Archive size={20} /></span>
      </header>

      <form className="repository-upload" onSubmit={(event) => void submit(event)}>
        <label className="repository-file-picker">
          <Upload size={19} />
          <span>{file ? file.name : "Escolher arquivo ZIP"}</span>
          <small>{file ? `${(file.size / 1_000_000).toFixed(2)} MB` : "Limite padrão: 25 MB"}</small>
          <input
            type="file"
            accept=".zip,application/zip"
            aria-label="Escolher arquivo ZIP do repositório"
            onChange={chooseFile}
          />
        </label>
        <button className="btn button-primary" type="submit" disabled={loading || !file || !apiEnabled}>
          {loading ? <LoaderCircle className="spin" size={16} /> : <FileCode2 size={16} />}
          {loading ? "Analisando arquivos..." : "Analisar repositório"}
        </button>
      </form>

      {!apiEnabled && (
        <div className="repository-notice" role="status">
          A análise de repositório precisa de uma sessão autenticada e da API configurada.
        </div>
      )}
      {error && <div className="error-notice" role="alert"><AlertTriangle size={15} /> {error}</div>}
      {loading && (
        <div className="repository-loading" role="status">
          <LoaderCircle className="spin" size={18} />
          <span>Enviando e analisando o ZIP. Arquivos grandes podem levar alguns instantes.</span>
        </div>
      )}
      {analysis && (
        <div className="repository-results">
          <div className="repository-result-heading">
            <div>
              <span className="detail-label">RESULTADO SALVO NO HISTÓRICO</span>
              <h3>{analysis.filename}</h3>
            </div>
            <span>{analysis.filesAnalyzed.length} arquivos analisados · {analysis.durationSeconds.toFixed(2)} s</span>
          </div>

          {(analysis.partial || analysis.findingsTruncated || analysis.pathsTruncated) && (
            <div className="repository-warning" role="status">
              <AlertTriangle size={16} />
              <span>
                {analysis.partial && `${analysis.filesNotAnalyzed.length} arquivo(s) ficaram sem análise. `}
                {analysis.findingsTruncated && `${analysis.truncatedFindingsCount} achado(s) e ${analysis.truncatedOccurrencesCount} ocorrência(s) foram omitidos para limitar o histórico. `}
                {analysis.pathsTruncated && "Alguns caminhos longos foram encurtados na exibição."}
              </span>
            </div>
          )}

          <div className="repository-summary-grid" aria-label="Achados por severidade">
            {severityOrder.map((severity) => (
              <div className="repository-summary-card" key={severity}>
                <span className={`finding-severity ${severityClass(severity)}`} />
                <strong>{displayedSeverityCounts[severity]}</strong>
                <span>{severity}</span>
              </div>
            ))}
            <div className="repository-summary-card repository-summary-total">
              <strong>{displayedOccurrenceCount}</strong>
              <span>ocorrências</span>
            </div>
          </div>

          <section className="repository-owasp-summary">
            <div className="detail-label">ACHADOS POR CATEGORIA OWASP</div>
            {Object.entries(displayedOwaspCounts).length ? (
              <ul>
                {Object.entries(displayedOwaspCounts)
                  .sort(([left], [right]) => left.localeCompare(right, "pt-BR"))
                  .map(([category, count]) => (
                    <li key={category}><span>{category}</span><strong>{count}</strong></li>
                  ))}
              </ul>
            ) : (
              <p>Nenhum achado nas categorias OWASP desta análise.</p>
            )}
          </section>

          {summary.files.length ? (
            <section className="repository-files">
              <div className="detail-label">ARQUIVOS COM ACHADOS · {summary.files.length}</div>
              {summary.files.map((repositoryFile) => (
                <details className="repository-file-result" key={repositoryFile.path}>
                  <summary>
                    <FileCode2 size={15} />
                    <code>{repositoryFile.path}</code>
                    <span>{repositoryFile.findings.length} regras · {repositoryFile.occurrences} ocorrências</span>
                  </summary>
                  <div className="repository-file-findings">
                    {repositoryFile.findings.map((finding) => (
                      <details className="repository-finding" key={finding.id}>
                        <summary>
                          <span className={`repository-severity-pill ${severityClass(finding.severity)}`}>{finding.severity}</span>
                          <strong>{finding.title}</strong>
                          <span>{finding.locations.length} linhas</span>
                        </summary>
                        <div className="repository-finding-detail">
                          <p>{finding.description}</p>
                          <div className="repository-evidence">
                            {finding.locations.map((line, index) => (
                              <div className="evidence-code" key={`${finding.id}-${line}-${index}`}>
                                <span>{String(line).padStart(3, "0")}</span>
                                <code>{finding.evidence[index] || "(linha vazia)"}</code>
                              </div>
                            ))}
                          </div>
                          <div className="repository-finding-recommendation">
                            <span className="detail-label">COMO CORRIGIR</span>
                            <p>{finding.recommendation}</p>
                          </div>
                          {finding.suggestedFix && (
                            <FindingFix fixes={finding.suggestedFix} locations={finding.locations} />
                          )}
                        </div>
                      </details>
                    ))}
                  </div>
                </details>
              ))}
            </section>
          ) : (
            <div className="repository-empty">
              Nenhum achado foi encontrado nos arquivos analisados.
            </div>
          )}

          {analysis.ignoredFiles.length > 0 && (
            <details className="repository-ignored">
              <summary>{analysis.ignoredFiles.length} arquivo(s) ou diretório(s) ignorado(s)</summary>
              <ul>
                {analysis.ignoredFiles.map((item, index) => (
                  <li key={`${item.path}-${index}`}><code>{item.path}</code><span>{item.reason}</span></li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </section>
  );
}
