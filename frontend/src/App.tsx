import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  BadgeCheck,
  BookOpenCheck,
  Braces,
  Bug,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Code2,
  Eye,
  EyeOff,
  FileCode2,
  FileDown,
  FileSearch,
  Fingerprint,
  Gauge,
  GitPullRequest,
  History,
  KeyRound,
  Layers3,
  LogOut,
  LockKeyhole,
  Mail,
  Menu,
  MessageSquare,
  Moon,
  MoveRight,
  ShieldCheck,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Sun,
  Upload,
  X,
  Zap,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
} from "react";
import { owaspCategories } from "./data/owasp";
import { analysisService, authenticateWithApi, logoutFromApi } from "./services/analysisService";
import type { Analysis, AnalysisInput, Finding } from "./types";

type View = "dashboard" | "scanner" | "coverage" | "history";
type InputMode = "paste" | "file";
type Theme = "dark" | "light";

const apiMode = Boolean((import.meta as ImportMeta & { env?: { VITE_API_URL?: string } }).env?.VITE_API_URL);
const THEME_STORAGE_KEY = "vibecheck.theme";

const demoSources = {
  python: {
    filename: "app.py",
    source: `import os
import pickle
import subprocess
import hashlib
import yaml
import requests

DEBUG = True
SECRET_KEY = "replace-me-with-a-real-secret"
password = "admin12345"

def find_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def calculate(expression):
    return eval(expression)

def ping(host):
    return subprocess.check_output("ping " + host, shell=True)

def restore_session(payload):
    return pickle.loads(payload)

def load_config(raw):
    return yaml.load(raw)

def fetch_url(url):
    return requests.get(url, verify=False)

def download(filename):
    return open(BASE_DIR + filename, "rb")

def hash_password(value):
    return hashlib.md5(value.encode()).hexdigest()
`,
  },
  javascript: {
    filename: "server.js",
    source: `const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const app = express();

const password = "demo-secret-password";
const secret = "replace-this-jwt-secret";

function hashPassword(value) {
  return crypto.createHash("md5").update(value).digest("hex");
}

app.get("/users/:id", (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  db.query(query);
});

function authenticate(token) {
  return jwt.verify(token, secret);
}

app.post("/convert", (req, res) => {
  exec(\`convert \${req.body.file} output.png\`);
});

const resetToken = Math.random().toString(36);
res.cookie("session", token, { httpOnly: true });
results.innerHTML = new URLSearchParams(location.search).get("q");
`,
  },
};

const scanStages = [
  { title: "Lendo o arquivo", detail: "Preparando o conteúdo no navegador", icon: FileCode2 },
  { title: "Mapeando padrões", detail: "Verificando a base de regras OWASP", icon: Radar },
  { title: "Cruzando evidências", detail: "Organizando severidades e localizações", icon: Fingerprint },
  { title: "Preparando resultado", detail: "Montando recomendações de correção", icon: Sparkles },
];
const MAX_BATCH_FILES = 20;

function severityStyle(severity: Finding["severity"]) {
  if (severity === "Crítica") return "critical";
  if (severity === "Alta") return "high";
  if (severity === "Média") return "medium";
  return "low";
}

function findingOccurrences(analysis: Analysis) {
  return analysis.findings.reduce(
    (total, finding) => total + finding.locations.length,
    0,
  );
}

function scoreFor(analysis: Analysis) {
  const weights = { Crítica: 5, Alta: 3, Média: 1.5, Baixa: 0.5 };
  const weighted = analysis.findings.reduce(
    (total, finding) =>
      total + weights[finding.severity] * finding.locations.length,
    0,
  );
  return Math.max(5, Math.round(100 * 0.86 ** weighted));
}

function IconBadge({
  children,
  tone = "violet",
}: {
  children: React.ReactNode;
  tone?: "violet" | "lime" | "red" | "blue";
}) {
  return <span className={`icon-badge tone-${tone}`}>{children}</span>;
}

function Logo() {
  return (
    <a className="brand" href="#inicio" aria-label="VibeCheck início">
      <span className="brand-mark">
        <img src="./vibecheck-icon.svg" alt="" />
      </span>
      <span className="brand-name">
        vibe<span>check</span>
      </span>
    </a>
  );
}

function ThemeToggle({
  theme,
  onToggle,
  className = "",
}: {
  theme: Theme;
  onToggle: () => void;
  className?: string;
}) {
  const label = theme === "dark" ? "Ativar tema claro" : "Ativar tema escuro";
  const Icon = theme === "dark" ? Sun : Moon;

  return (
    <button
      className={`theme-toggle ${className}`}
      type="button"
      aria-label={label}
      title={label}
      onClick={onToggle}
    >
      <Icon size={16} />
      <span>{label}</span>
    </button>
  );
}

function FindingRow({
  finding,
  filename,
}: {
  finding: Finding;
  filename: string;
}) {
  const [open, setOpen] = useState(false);

  return (
    <article className={`finding-row ${open ? "is-open" : ""}`}>
      <button
        className="finding-summary"
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <span className={`finding-severity ${severityStyle(finding.severity)}`}>
          {finding.severity === "Crítica" ? <AlertTriangle size={14} /> : <Bug size={14} />}
        </span>
        <span className="finding-summary-copy">
          <strong>{finding.title}</strong>
          <span>
            {finding.owaspId}:2025 <span className="bullet-divider">·</span>{" "}
            {finding.cwe}
          </span>
        </span>
        <span className="finding-location">
          <FileCode2 size={13} />
          {finding.locations.length === 1
            ? `linha ${finding.locations[0]}`
            : `${finding.locations.length} linhas`}
          <ChevronDown className="finding-chevron" size={15} />
        </span>
      </button>
      {open && (
        <div className="finding-expanded">
          <div className="finding-description">
            <span className="detail-label">O QUE ENCONTRAMOS</span>
            <p>{finding.description}</p>
          </div>
          <div className="evidence-list">
            <span className="detail-label">EVIDÊNCIA NO ARQUIVO</span>
            {finding.evidence.map((evidence, index) => (
              <div className="evidence-code" key={`${finding.id}-${finding.locations[index]}`}>
                <span>{String(finding.locations[index]).padStart(3, "0")}</span>
                <code>{evidence || "(linha vazia)"}</code>
              </div>
            ))}
            <p className="evidence-file">{filename}</p>
          </div>
          <div className="finding-action-grid">
            <div className="action-card action-fix">
              <span className="detail-label"><CheckCircle2 size={13} /> COMO CORRIGIR</span>
              <p>{finding.recommendation}</p>
            </div>
            <div className="action-card action-impact">
              <span className="detail-label"><AlertTriangle size={13} /> SE FICAR ASSIM</span>
              <p>{finding.impact}</p>
            </div>
            <div className="action-card action-prevent">
              <span className="detail-label"><ShieldCheck size={13} /> COMO EVITAR DEPOIS</span>
              <p>{finding.prevention}</p>
            </div>
          </div>
          <a
            className="owasp-learn-link"
            href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`}
            target="_blank"
            rel="noreferrer"
          >
            Saiba mais sobre {finding.cwe} <ArrowUpRight size={13} />
          </a>
        </div>
      )}
    </article>
  );
}

function OwaspPanel({
  findings,
  hasAnalysis,
  onBack,
  onViewFindings,
}: {
  findings: Finding[];
  hasAnalysis: boolean;
  onBack: () => void;
  onViewFindings: (categoryId: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "findings" | "manual">("all");

  const categoryCounts = useMemo(() => {
    const counts = new Map<string, Finding[]>();
    findings.forEach((finding) => {
      counts.set(finding.owaspId, [...(counts.get(finding.owaspId) ?? []), finding]);
    });
    return counts;
  }, [findings]);

  const filteredCategories = useMemo(() => {
    const normalizedSearch = search.trim().toLocaleLowerCase("pt-BR");
    return owaspCategories.filter((category) => {
      const categoryFindings = categoryCounts.get(category.id) ?? [];
      if (filter === "findings" && categoryFindings.length === 0) return false;
      if (filter === "manual" && category.automated) return false;
      if (!normalizedSearch) return true;
      return [
        category.id,
        category.name,
        category.title,
        category.guidance,
        ...categoryFindings.map((finding) => finding.title),
      ].some((value) => value.toLocaleLowerCase("pt-BR").includes(normalizedSearch));
    });
  }, [categoryCounts, filter, search]);

  const flaggedCategories = categoryCounts.size;
  const categoriesWithAutomation = owaspCategories.filter((category) => category.automated).length;
  const manualReviewCount = owaspCategories.length - categoriesWithAutomation;
  const occurrenceCount = findings.reduce((total, finding) => total + finding.locations.length, 0);

  return (
    <section className="workspace-card coverage-section">
      <div className="coverage-hero">
        <div className="coverage-hero-copy">
          <div className="eyebrow welcome-eyebrow">
            <span className="eyebrow-spark"><Layers3 size={12} /></span>
            REFERÊNCIA DE SEGURANÇA
          </div>
          <h2>OWASP Top 10 <span className="heading-year">2025</span></h2>
          <p>
            Entenda o que cada categoria cobre, quais sinais apareceram na análise
            e onde uma revisão humana ainda é importante.
          </p>
        </div>
        <button className="btn button-secondary coverage-back-button" onClick={onBack} type="button">
          <ArrowRight className="coverage-back-icon" size={14} /> Voltar à análise
        </button>
      </div>

      <div className="coverage-overview" aria-label="Resumo da cobertura OWASP">
        <article className={`coverage-overview-card ${hasAnalysis && flaggedCategories ? "coverage-overview-risk" : ""}`}>
          <span className="coverage-overview-icon"><ShieldAlert size={16} /></span>
          <span className="coverage-overview-copy"><small>{hasAnalysis ? "CATEGORIAS COM SINAIS" : "ANÁLISE NECESSÁRIA"}</small><strong>{hasAnalysis ? `${flaggedCategories}` : "—"}<span>{hasAnalysis ? ` / ${owaspCategories.length}` : ""}</span></strong></span>
          <span className="coverage-overview-note">{hasAnalysis ? `${occurrenceCount} ocorrência(s)` : "Aguardando análise de código"}</span>
        </article>
        <article className="coverage-overview-card">
          <span className="coverage-overview-icon"><Eye size={16} /></span>
          <span className="coverage-overview-copy"><small>REVISÃO HUMANA</small><strong>{manualReviewCount}<span> categoria</span></strong></span>
          <span className="coverage-overview-note">Design inseguro</span>
        </article>
      </div>

      {hasAnalysis && (
        <div className="coverage-progress" aria-label={`${flaggedCategories} de 10 categorias com sinais`}>
          <div className="coverage-progress-copy">
            <strong>Visão desta análise</strong>
            <span>{flaggedCategories} de {owaspCategories.length} categorias têm sinais correspondentes às regras atuais.</span>
          </div>
          <div className="coverage-progress-track">
            <span style={{ width: `${flaggedCategories / owaspCategories.length * 100}%` }} />
          </div>
          <strong className="coverage-progress-value">{Math.round(flaggedCategories / owaspCategories.length * 100)}%</strong>
        </div>
      )}

      <div className="coverage-controls">
        <label className="coverage-search">
          <Search size={15} />
          <input
            aria-label="Buscar categoria ou achado OWASP"
            placeholder="Buscar categoria ou achado..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          {search && <button type="button" aria-label="Limpar busca OWASP" onClick={() => setSearch("")}><X size={13} /></button>}
        </label>
        <div className="coverage-filter-tabs" role="group" aria-label="Filtrar categorias OWASP">
          {([
            ["all", "Todas", owaspCategories.length],
            ["findings", "Com sinais", hasAnalysis ? flaggedCategories : null],
            ["manual", "Revisão manual", manualReviewCount],
          ] as const).map(([value, label, count]) => (
            <button
              type="button"
              className={filter === value ? "active" : ""}
              aria-pressed={filter === value}
              key={value}
              onClick={() => setFilter(value)}
            >
              {label}{count !== null && <span>{count}</span>}
            </button>
          ))}
        </div>
      </div>

      {filteredCategories.length ? (
        <div className="owasp-grid">
          {filteredCategories.map((category, index) => {
            const categoryFindings = categoryCounts.get(category.id) ?? [];
            const occurrenceCountForCategory = categoryFindings.reduce(
              (total, finding) => total + finding.locations.length,
              0,
            );
            return (
              <article
                className={`owasp-card ${categoryFindings.length ? "has-findings" : ""}`}
                key={category.id}
                style={{ animationDelay: `${Math.min(index, 9) * 25}ms` }}
              >
                <div className="owasp-card-top">
                  <span className="owasp-id">{category.id}</span>
                  <span className={`owasp-status ${categoryFindings.length ? "flagged" : hasAnalysis ? "review" : "pending"}`}>
                    {categoryFindings.length
                      ? `${occurrenceCountForCategory} sinal(is)`
                      : hasAnalysis
                        ? "Sem sinal detectado"
                        : "Aguardando análise"}
                  </span>
                </div>
                <h3>{category.title}</h3>
                <p className="owasp-card-english">{category.name}</p>
                <p className="owasp-card-guidance">{category.guidance}</p>
                <div className="owasp-card-meta">
                  <span className={`owasp-method ${category.automated ? "automated" : "manual"}`}>
                    {category.automated ? <ScanLine size={12} /> : <Eye size={12} />}
                    {category.automated ? "Heurísticas + revisão contextual" : "Requer revisão manual"}
                  </span>
                  <a
                    className="owasp-external-link"
                    href={category.url}
                    target="_blank"
                    rel="noreferrer"
                    aria-label={`Abrir documentação OWASP de ${category.title}`}
                  >
                    OWASP <ArrowUpRight size={12} />
                  </a>
                </div>
                {categoryFindings.length > 0 && (
                  <div className="owasp-findings">
                    <div className="owasp-findings-heading">
                      <strong>Achados relacionados</strong>
                      <span>{categoryFindings.length}</span>
                    </div>
                    {categoryFindings.slice(0, 3).map((finding) => (
                      <div className="owasp-finding-item" key={finding.id}>
                        <span className={`severity-dot ${severityStyle(finding.severity)}`} />
                        <span>{finding.title}</span>
                        <small>{finding.locations.length === 1 ? `linha ${finding.locations[0]}` : `${finding.locations.length} linhas`}</small>
                      </div>
                    ))}
                    {categoryFindings.length > 3 && <span className="owasp-more-findings">+{categoryFindings.length - 3} categoria(s) de achado</span>}
                    <button className="owasp-view-findings" type="button" onClick={() => onViewFindings(category.id)}>
                      Abrir relatório da análise <ArrowRight size={13} />
                    </button>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      ) : (
        <div className="coverage-no-results">
          <Search size={19} />
          <strong>Nenhuma categoria encontrada</strong>
          <span>Ajuste a busca ou escolha outro filtro.</span>
          <button type="button" onClick={() => { setSearch(""); setFilter("all"); }}>Limpar filtros</button>
        </div>
      )}

      <div className="coverage-footnote">
        <AlertTriangle size={16} />
        <span><strong>Importante sobre a cobertura</strong>“Sem sinal” significa que as regras heurísticas atuais não encontraram um padrão correspondente neste arquivo. Isso não comprova a ausência de vulnerabilidades; algumas categorias exigem contexto, análise de fluxo ou validação manual.</span>
      </div>
      <div className="coverage-resources">
        <span>REFERÊNCIAS PARA APROFUNDAR</span>
        <div className="source-links">
          <a href="https://top10.owasp.org/2025/" target="_blank" rel="noreferrer">
            OWASP Top 10 oficial <ArrowUpRight size={13} />
          </a>
          <a href="https://owasp.org/www-project-benchmark/" target="_blank" rel="noreferrer">
            OWASP Benchmark <ArrowUpRight size={13} />
          </a>
          <a href="https://owasp.org/www-project-application-security-verification-standard/" target="_blank" rel="noreferrer">
            OWASP ASVS <ArrowUpRight size={13} />
          </a>
        </div>
      </div>
    </section>
  );
}

function MarketingPage({
  onLogin,
  onSignup,
  theme,
  onToggleTheme,
}: {
  onLogin: () => void;
  onSignup: () => void;
  theme: Theme;
  onToggleTheme: () => void;
}) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div className="marketing-shell">
      <header className="marketing-nav">
        <Logo />
        <nav
          id="marketing-navigation"
          className={`marketing-nav-links ${mobileNavOpen ? "is-open" : ""}`}
          aria-label="Navegação principal"
        >
          <a href="#recursos" onClick={() => setMobileNavOpen(false)}>Recursos</a>
          <a href="#analise-em-lote" onClick={() => setMobileNavOpen(false)}>Análise em lote</a>
          <a href="#como-funciona" onClick={() => setMobileNavOpen(false)}>Como funciona</a>
          <a href="#cobertura" onClick={() => setMobileNavOpen(false)}>Cobertura</a>
          <a href="#integracao" onClick={() => setMobileNavOpen(false)}>GitHub</a>
        </nav>
        <div className="marketing-nav-actions">
          <button
            type="button"
            className="marketing-menu-toggle"
            aria-label={mobileNavOpen ? "Fechar menu de navegação" : "Abrir menu de navegação"}
            aria-controls="marketing-navigation"
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen((open) => !open)}
          >
            {mobileNavOpen ? <X size={19} /> : <Menu size={19} />}
          </button>
          <ThemeToggle theme={theme} onToggle={onToggleTheme} className="marketing-theme-toggle" />
          <button type="button" className="marketing-login" onClick={onLogin}>Entrar</button>
          <button type="button" className="button-primary marketing-cta" onClick={onSignup}>
            Começar agora <ArrowRight size={15} />
          </button>
        </div>
      </header>

      <main>
        <section className="marketing-hero">
          <div className="hero-copy">
            <div className="eyebrow welcome-eyebrow">
              <span className="eyebrow-spark"><Sparkles size={12} /></span>
              SEGURANÇA DE APLICAÇÕES, SEM FRICÇÃO
            </div>
            <h1>Encontre riscos.<br /><span>Entenda como agir.</span></h1>
            <p>
              Analise trechos de código, encontre padrões de risco e receba
              orientações claras para corrigir e prevenir — sem sair do navegador.
            </p>
            <div className="hero-actions">
              <button type="button" className="button-primary" onClick={onSignup}>
                Analisar meu código <ArrowRight size={16} />
              </button>
              <a className="hero-secondary" href="#como-funciona">
                Conhecer a plataforma <MoveRight size={15} />
              </a>
            </div>
            <div className="hero-trust">
              <span><LockKeyhole size={14} /> {apiMode ? "Autenticação e histórico no backend" : "Código processado localmente"}</span>
              <span><ShieldCheck size={14} /> {apiMode ? "API conectada e sessão ativa" : "Modo local de demonstração"}</span>
            </div>
          </div>
          <div className="hero-art" aria-label="Prévia ilustrativa da análise">
            <div className="hero-art-glow" />
            <div className="hero-art-grid" />
            <div className="hero-scan-window">
              <div className="hero-window-bar">
                <span><i /><i /><i /></span>
                <span>api / users.py</span>
                <span className="hero-live"><i /> SCAN</span>
              </div>
              <div className="hero-code-lines">
                <span><i>12</i> <b>def</b> get_user(user_id):</span>
                <span><i>13</i> &nbsp; query = <em>{'f"SELECT ... {user_id}"'}</em></span>
                <span className="hero-code-alert"><i>14</i> &nbsp; return db.execute(query)</span>
                <span><i>15</i></span>
              </div>
              <div className="hero-finding-float">
                <span className="finding-severity critical"><AlertTriangle size={14} /></span>
                <span><strong>SQL Injection</strong><small>app.py · linha 14</small></span>
                <span className="hero-critical-label">CRÍTICO</span>
              </div>
              <div className="hero-scan-status"><span /> 21 verificações concluídas <CheckCircle2 size={14} /></div>
            </div>
            <span className="hero-orbit hero-orbit-one" />
            <span className="hero-orbit hero-orbit-two" />
            <span className="hero-art-chip"><ShieldCheck size={14} /> PRIVADO POR PADRÃO</span>
          </div>
          <div className="hero-bottom-note"><span /> DEMONSTRAÇÃO FRONTEND · VERSÃO LOCAL 0.2</div>
        </section>

        <section className="marketing-proof" aria-label="Resumo do protótipo">
          <div><strong>21</strong><span>checagens heurísticas</span></div>
          <i />
          <div><strong>10</strong><span>categorias OWASP</span></div>
          <i />
          <div><strong>{apiMode ? "API" : "0"}</strong><span>{apiMode ? "análises enviadas ao backend" : "envios ao servidor no modo local"}</span></div>
          <i />
          <div><strong>20</strong><span>arquivos por lote</span></div>
        </section>

        <section className="marketing-section" id="recursos">
          <div className="marketing-section-heading">
            <span className="eyebrow">UM FLUXO DE TRABALHO, NÃO SÓ UM ALERTA</span>
            <h2>Da primeira linha ao<br /><span>plano de correção.</span></h2>
            <p>
              Entenda o que chamou atenção, onde está o padrão e quais passos
              considerar antes de publicar.
            </p>
          </div>
          <div className="marketing-feature-grid">
            <article className="marketing-feature feature-purple">
              <span className="feature-icon"><ScanLine size={19} /></span>
              <span className="eyebrow">01 / ANALISAR</span>
              <h3>Revise vários arquivos de uma vez.</h3>
              <p>Selecione ou arraste até 20 arquivos de texto, com limite de 1 MB cada, ou cole um trecho. No modo local, o conteúdo fica no navegador.</p>
              <div className="feature-decoration"><Code2 size={74} strokeWidth={0.7} /></div>
            </article>
            <article className="marketing-feature feature-red">
              <span className="feature-icon"><Bug size={19} /></span>
              <span className="eyebrow">02 / ENTENDER</span>
              <h3>Veja o contexto, não só a severidade.</h3>
              <p>Explore evidências, linhas, referências CWE/OWASP, impacto potencial e recomendações para investigar cada sinal.</p>
              <div className="feature-decoration"><Fingerprint size={74} strokeWidth={0.7} /></div>
            </article>
            <article className="marketing-feature feature-lime">
              <span className="feature-icon"><FileDown size={19} /></span>
              <span className="eyebrow">03 / AGIR</span>
              <h3>Leve um relatório para o próximo passo.</h3>
              <p>Exporte os achados para PDF com resumo, prioridades, localizações e dicas para reduzir a recorrência dos mesmos padrões.</p>
              <div className="feature-decoration"><ShieldCheck size={74} strokeWidth={0.7} /></div>
            </article>
          </div>
        </section>

        <section className="marketing-batch" id="analise-em-lote">
          <div className="batch-copy">
            <span className="eyebrow">ANÁLISE EM LOTE · ATÉ 20 ARQUIVOS</span>
            <h2>Mais arquivos.<br /><span>Um fluxo claro.</span></h2>
            <p>
              Rode uma análise por arquivo, acompanhe o progresso e alterne entre
              relatórios individuais. Cada resultado continua ligado ao seu
              próprio código e localização.
            </p>
            <div className="batch-benefits">
              <span><CheckCircle2 size={15} /> Seleção múltipla ou arrastar e soltar</span>
              <span><CheckCircle2 size={15} /> Relatório separado para cada arquivo</span>
              <span><CheckCircle2 size={15} /> Limite de 1 MB por arquivo</span>
            </div>
            <button type="button" className="text-link" onClick={onSignup}>
              Experimentar análise em lote <ArrowRight size={14} />
            </button>
          </div>
          <div className="batch-visual" aria-label="Prévia ilustrativa de análise em lote">
            <div className="batch-visual-orbit batch-visual-orbit-one" />
            <div className="batch-visual-orbit batch-visual-orbit-two" />
            <div className="batch-scan-beam" />
            <div className="batch-visual-heading"><Layers3 size={15} /> REVISÃO DE ARQUIVOS <span>3 / 20</span></div>
            <article className="batch-file-card batch-file-one">
              <span className="batch-file-icon"><FileCode2 size={15} /></span>
              <span><strong>auth.ts</strong><small>TypeScript · 148 linhas</small></span>
              <CheckCircle2 size={15} />
            </article>
            <article className="batch-file-card batch-file-two">
              <span className="batch-file-icon batch-file-icon-risk"><Code2 size={15} /></span>
              <span><strong>routes.py</strong><small>Python · 92 linhas</small></span>
              <span className="batch-file-count">2 sinais</span>
            </article>
            <article className="batch-file-card batch-file-three">
              <span className="batch-file-icon"><Braces size={15} /></span>
              <span><strong>config.json</strong><small>JSON · 34 linhas</small></span>
              <CheckCircle2 size={15} />
            </article>
            <div className="batch-progress"><span /></div>
            <span className="batch-visual-note"><ScanLine size={13} /> Um relatório por arquivo</span>
          </div>
        </section>

        <section className="marketing-process" id="como-funciona">
          <div className="process-copy">
            <span className="eyebrow">SIMPLES, TRANSPARENTE, LOCAL</span>
            <h2>Segurança com<br /><span>clareza em cada etapa.</span></h2>
            <p>
              As heurísticas rodam no navegador por padrão. Com a API configurada,
              as análises também podem ser enviadas ao backend e salvas no histórico.
            </p>
            <button type="button" className="text-link" onClick={onSignup}>Experimentar a demonstração <ArrowRight size={14} /></button>
          </div>
          <div className="process-steps">
            <article><span>01</span><div><strong>Escolha o código</strong><p>Envie um arquivo pequeno ou use um dos exemplos incluídos.</p></div><Upload size={17} /></article>
            <article><span>02</span><div><strong>Acompanhe a análise</strong><p>Veja o progresso e os padrões encontrados pelas regras ativas.</p></div><Activity size={17} /></article>
            <article><span>03</span><div><strong>Revise e exporte</strong><p>Investigue os detalhes e gere um relatório PDF local.</p></div><FileDown size={17} /></article>
          </div>
        </section>

        <section className="marketing-owasp" id="cobertura">
          <div>
            <span className="eyebrow">UMA REFERÊNCIA, NÃO UMA PROMESSA</span>
            <h2>Alinhado ao<br /><span>OWASP Top 10:2025.</span></h2>
            <p>
              As regras demonstrativas mapeiam alguns padrões às categorias
              OWASP. O Top 10 é uma orientação de conscientização, não uma
              checklist de conformidade nem cobertura completa.
            </p>
            <a className="text-link" href="https://top10.owasp.org/2025/" target="_blank" rel="noreferrer">
              Consultar fonte oficial <ArrowUpRight size={14} />
            </a>
          </div>
          <div className="marketing-owasp-list">
            {owaspCategories.map((category) => (
              <a href={category.url} target="_blank" rel="noreferrer" key={category.id}>
                <span>{category.id}</span><strong>{category.title}</strong>
                <span className={category.automated ? "map-status" : "map-manual"}>
                  {category.automated ? "heurísticas + contexto" : "revisão manual"}
                </span>
                <ArrowUpRight size={13} />
              </a>
            ))}
          </div>
        </section>

        <section className="marketing-integration" id="integracao">
          <div className="integration-copy">
            <span className="eyebrow">DO CÓDIGO AO PULL REQUEST</span>
            <h2>Segurança mais perto<br /><span>do seu fluxo.</span></h2>
            <p>
              O repositório inclui um workflow de GitHub Actions que analisa
              linhas adicionadas em Pull Requests e pode publicar comentários
              inline. A execução depende de o workflow estar habilitado no
              repositório.
            </p>
            <div className="integration-tags">
              <span><GitPullRequest size={14} /> Pull Requests</span>
              <span><MessageSquare size={14} /> Comentários inline</span>
              <span><ShieldCheck size={14} /> Revisão heurística</span>
            </div>
          </div>
          <div className="integration-preview">
            <div className="integration-preview-bar"><span><i /><i /><i /></span><strong>GitHub Actions</strong><span className="integration-status"><span /> workflow</span></div>
            <div className="integration-pr"><GitPullRequest size={16} /><span><strong>Revisão do Pull Request</strong><small>Verifica apenas linhas novas suportadas</small></span><CheckCircle2 size={16} /></div>
            <div className="integration-comment"><span className="integration-comment-icon"><Bug size={14} /></span><span><strong>Possível risco identificado</strong><small>Comentário associado à linha alterada, com contexto e recomendação.</small></span></div>
            <p>O scanner é heurístico; a ausência de comentários não garante ausência de vulnerabilidades.</p>
          </div>
        </section>

        <section className="marketing-bottom-cta">
          <div className="cta-decoration"><ShieldCheck size={47} strokeWidth={1.2} /></div>
          <span className="eyebrow">SEU PRÓXIMO COMMIT PODE SER MAIS SEGURO</span>
          <h2>Vamos começar pelo código?</h2>
          <p>Explore a experiência de análise gratuita neste protótipo frontend.</p>
          <button type="button" className="button-primary" onClick={onSignup}>Abrir demonstração <ArrowRight size={15} /></button>
        </section>
      </main>

      <footer className="marketing-footer">
        <Logo />
        <span>{apiMode ? "Workspace com autenticação e análise via backend" : "Modo local do frontend"}</span>
        <a href="https://top10.owasp.org/2025/" target="_blank" rel="noreferrer">OWASP Top 10:2025 <ArrowUpRight size={12} /></a>
      </footer>
    </div>
  );
}

type AuthMode = "login" | "signup" | "reset";

function AuthPage({
  mode,
  onModeChange,
  onAuthenticate,
  onBack,
}: {
  mode: AuthMode;
  onModeChange: (mode: AuthMode) => void;
  onAuthenticate: (email: string, password: string, mode: "login" | "signup") => Promise<void>;
  onBack: () => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const isSignup = mode === "signup";

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setNotice("");
    if (mode === "reset") {
      setNotice("A recuperação de senha está disponível pela API quando o SMTP estiver configurado.");
      return;
    }
    if (password.length < 8) {
      setError("Use uma senha com pelo menos 8 caracteres.");
      return;
    }
    try {
      await onAuthenticate(email.trim(), password, mode);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível entrar. Verifique a API.");
    }
  }

  return (
    <main className="auth-shell">
      <div className="auth-ambient auth-ambient-one" />
      <div className="auth-ambient auth-ambient-two" />
      <header className="auth-topbar">
        <Logo />
        <button className="auth-back-link" type="button" onClick={onBack}>
          <ArrowRight size={14} /> Voltar ao início
        </button>
      </header>
      <div className="auth-layout">
        <section className="auth-story">
          <span className="eyebrow"><span className="online-indicator" /> {apiMode ? "AMBIENTE COM BACKEND" : "AMBIENTE LOCAL"}</span>
          <h1>Segurança começa<br />com <span>visibilidade.</span></h1>
          <p>{apiMode ? "Entre com sua conta para acessar o histórico, a sessão e o workspace com backend ativo." : "Entre no workspace local para experimentar a análise, explorar os achados e gerar um relatório demonstrativo."}</p>
          <div className="auth-story-list">
            <span><CheckCircle2 size={15} /> {apiMode ? "Sessão e histórico persistidos no backend" : "Código permanece no navegador"}</span>
            <span><CheckCircle2 size={15} /> {apiMode ? "Conta e autenticação do projeto" : "Sem servidor ou conta real"}</span>
            <span><CheckCircle2 size={15} /> {apiMode ? "Dados isolados por usuário" : "Dados limitados a esta sessão"}</span>
          </div>
          <div className="auth-story-visual" aria-hidden="true">
            <div className="story-orbit story-orbit-a" />
            <div className="story-orbit story-orbit-b" />
            <div className="story-shield"><ShieldCheck size={42} /></div>
            <span className="story-node node-a"><LockKeyhole size={13} /></span>
            <span className="story-node node-b"><ScanLine size={13} /></span>
          </div>
        </section>
        <section className="auth-card" aria-labelledby="auth-title">
          <div className="auth-card-brand"><Logo /><span className="auth-local-badge"><i /> {apiMode ? "BACKEND ATIVO" : "LOCAL DEMO"}</span></div>
          <div className="auth-card-heading">
            <span className="eyebrow">{mode === "reset" ? "RECUPERAÇÃO DE ACESSO" : isSignup ? "CRIE SUA CONTA" : "BEM-VINDO DE VOLTA"}</span>
            <h2 id="auth-title">{mode === "reset" ? "Recuperar acesso" : isSignup ? "Vamos começar." : "Entre no workspace."}</h2>
            <p>{mode === "reset" ? (apiMode ? "Use a recuperação de senha da API quando o SMTP estiver configurado." : "Teste a interface de recuperação — nenhum e-mail será enviado.") : isSignup ? (apiMode ? "Crie sua conta no backend do projeto para acessar histórico e sessão." : "O cadastro é fictício e existe apenas nesta sessão.") : (apiMode ? "Entre com sua conta para continuar no workspace." : "Use a conta de demonstração para explorar o protótipo.")}</p>
          </div>
          <form className="auth-form" onSubmit={submit}>
            <label htmlFor="auth-email">E-mail</label>
            <div className="auth-input-wrap">
              <Mail size={16} />
              <input id="auth-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="voce@empresa.com" />
            </div>
            {mode !== "reset" && (
              <>
                <div className="auth-label-row">
                  <label htmlFor="auth-password">Senha</label>
                  {!isSignup && <button type="button" onClick={() => { setError(""); setNotice(""); onModeChange("reset"); }}>Esqueceu a senha?</button>}
                </div>
                <div className="auth-input-wrap">
                  <KeyRound size={16} />
                  <input id="auth-password" type={showPassword ? "text" : "password"} autoComplete={isSignup ? "new-password" : "current-password"} required minLength={8} value={password} onChange={(event) => setPassword(event.target.value)} placeholder={isSignup ? "Mínimo de 8 caracteres" : "Digite a senha demonstrativa"} />
                  <button className="password-toggle" type="button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? "Ocultar senha" : "Mostrar senha"}>
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </>
            )}
            {error && <div className="error-notice" role="alert"><AlertTriangle size={15} /> {error}</div>}
            {notice && <div className="auth-notice" role="status"><CheckCircle2 size={15} /> {notice}</div>}
            <button className="btn button-primary auth-submit" type="submit">
              {mode === "reset" ? "Solicitar recuperação" : isSignup ? "Criar conta" : "Entrar"}
              <ArrowRight size={15} />
            </button>
          </form>
          {mode === "login" && (
            <div className="demo-credentials">
              <span className="eyebrow">ACESSO DE DESENVOLVIMENTO</span>
              <span>Crie uma conta na opção “Criar conta”.</span>
              <span>Conta demo disponível somente se habilitada no backend.</span>
            </div>
          )}
          <div className="auth-mode-switch">
            {mode === "reset" ? (
              <button type="button" onClick={() => { setNotice(""); onModeChange("login"); }}>Voltar ao login</button>
            ) : isSignup ? (
              <span>Já tem acesso? <button type="button" onClick={() => { setError(""); onModeChange("login"); }}>Entrar</button></span>
            ) : (
              <span>Novo por aqui? <button type="button" onClick={() => { setError(""); onModeChange("signup"); }}>Criar conta</button></span>
            )}
          </div>
          <div className="auth-disclaimer"><LockKeyhole size={13} /> {apiMode ? "Autenticação via API local do projeto. Use uma senha válida para o ambiente." : "Modo local do frontend. Não use uma senha pessoal."}</div>
        </section>
      </div>
      <footer className="auth-footer"><span>{apiMode ? "VIBECHECK · BACKEND + FRONTEND" : "VIBECHECK · FRONTEND DEMONSTRATIVO"}</span><a href="https://top10.owasp.org/2025/" target="_blank" rel="noreferrer">OWASP Top 10:2025 <ArrowUpRight size={12} /></a></footer>
    </main>
  );
}

function App() {
  const [portal, setPortal] = useState<"landing" | "auth" | "workspace">("landing");
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [userEmail, setUserEmail] = useState("");
  const [theme, setTheme] = useState<Theme>(() => (
    localStorage.getItem(THEME_STORAGE_KEY) === "light" ? "light" : "dark"
  ));
  const [view, setView] = useState<View>("dashboard");
  const [mode, setMode] = useState<InputMode>("file");
  const [source, setSource] = useState("");
  const [filename, setFilename] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<AnalysisInput[]>([]);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [batchResults, setBatchResults] = useState<Analysis[]>([]);
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number; filename: string } | null>(null);
  const [history, setHistory] = useState<Analysis[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [stage, setStage] = useState(-1);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [filter, setFilter] = useState("Todas");
  const [owaspCategoryFilter, setOwaspCategoryFilter] = useState<string | null>(null);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [reportError, setReportError] = useState("");
  const [isDownloadingReport, setIsDownloadingReport] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLElement>(null);

  const reloadHistory = useCallback(async () => {
    try {
      setHistory(await analysisService.getHistory());
      setHistoryLoaded(true);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Não foi possível carregar o histórico local.",
      );
    }
  }, []);

  useEffect(() => {
    void reloadHistory();
  }, [reloadHistory]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  const counts = useMemo(() => {
    if (!analysis) return { critical: 0, high: 0, medium: 0, occurrences: 0 };
    return analysis.findings.reduce(
      (total, finding) => {
        const occurrences = finding.locations.length;
        if (finding.severity === "Crítica") total.critical += occurrences;
        else if (finding.severity === "Alta") total.high += occurrences;
        else total.medium += occurrences;
        total.occurrences += occurrences;
        return total;
      },
      { critical: 0, high: 0, medium: 0, occurrences: 0 },
    );
  }, [analysis]);

  const filteredFindings = useMemo(() => {
    if (!analysis) return [];
    return analysis.findings.filter((finding) => (
      (!owaspCategoryFilter || finding.owaspId === owaspCategoryFilter) &&
      (filter === "Todas" || finding.severity === filter)
    ));
  }, [analysis, filter, owaspCategoryFilter]);
  const activeOwaspCategory = owaspCategories.find(
    (category) => category.id === owaspCategoryFilter,
  );

  function setViewAndClose(nextView: View) {
    setView(nextView);
    setSidebarOpen(false);
    setError("");
    if (nextView === "scanner") setOwaspCategoryFilter(null);
  }

  async function loadFiles(fileList: FileList | File[]) {
    const files = Array.from(fileList);
    if (!files.length) return;
    if (files.length > MAX_BATCH_FILES) {
      setError(`Selecione no máximo ${MAX_BATCH_FILES} arquivos por análise.`);
      return;
    }

    const oversized = files.filter((file) => file.size > 1_000_000);
    const validFiles = files.filter((file) => file.size <= 1_000_000);
    try {
      const inputs = await Promise.all(
        validFiles.map(async (file) => ({ filename: file.name, source: await file.text() })),
      );
      setSelectedFiles(inputs);
      setFilename(inputs[0]?.filename ?? "");
      setSource(inputs[0]?.source ?? "");
      setMode("file");
      setAnalysis(null);
      setBatchResults([]);
      setError(
        oversized.length
          ? `${oversized.map((file) => file.name).join(", ")}: limite de 1 MB por arquivo excedido; ${oversized.length === 1 ? "este arquivo não foi adicionado" : "estes arquivos não foram adicionados"}.`
          : "",
      );
    } catch {
      setError("Não foi possível ler os arquivos selecionados. Verifique se são arquivos de texto UTF-8.");
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    if (event.target.files) void loadFiles(event.target.files);
    event.target.value = "";
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    void loadFiles(event.dataTransfer.files);
  }

  async function runAnalysis(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const inputs: AnalysisInput[] = mode === "file"
      ? selectedFiles
      : [{ filename: filename || "codigo-colado.txt", source }];
    if (!inputs.length) {
      setError("Escolha ao menos um arquivo para iniciar.");
      return;
    }
    const emptyInputs = inputs.filter((input) => !input.source.trim());
    const analyzableInputs = inputs.filter((input) => input.source.trim());
    if (!analyzableInputs.length) {
      setError(mode === "file"
        ? `Não há conteúdo para analisar: ${emptyInputs.map((input) => input.filename).join(", ")}.`
        : "Cole o código que deseja analisar.");
      return;
    }
    if (analyzableInputs.some((input) => new Blob([input.source]).size > 1_000_000)) {
      setError("Cada arquivo ou trecho deve ter no máximo 1 MB.");
      return;
    }

    setError("");
    setAnalysis(null);
    setBatchResults([]);
    setBatchProgress(null);
    setIsScanning(true);
    setStage(0);
    const wait = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));
    try {
      await wait(260);
      setStage(1);
      await wait(340);
      setStage(2);
      await wait(300);
      const completed: Analysis[] = [];
      const failures = emptyInputs.map((input) => `${input.filename}: arquivo vazio`);
      for (const [index, input] of analyzableInputs.entries()) {
        setBatchProgress({ current: index + 1, total: analyzableInputs.length, filename: input.filename });
        try {
          completed.push(await analysisService.analyze(input));
        } catch (cause) {
          const reason = cause instanceof Error ? cause.message : "erro inesperado";
          failures.push(`${input.filename}: ${reason}`);
        }
      }

      setStage(3);
      await wait(240);
      setBatchResults(completed);
      setAnalysis(completed[0] ?? null);
      setFilter("Todas");
      setOwaspCategoryFilter(null);
      setError(failures.length ? `Não foi possível analisar ${failures.join(" · ")}` : "");
      if (completed.length) {
        await reloadHistory();
        window.setTimeout(
          () => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }),
          120,
        );
      } else {
        setStage(-1);
      }
    } finally {
      setIsScanning(false);
      setBatchProgress(null);
    }
  }

  function useDemo(which: keyof typeof demoSources) {
    const demo = demoSources[which];
    setFilename(demo.filename);
    setSource(demo.source);
    setSelectedFiles([]);
    setMode("paste");
    setAnalysis(null);
    setBatchResults([]);
    setError("");
    setView("scanner");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function clearHistory() {
    try {
      await analysisService.clearHistory();
      setHistory([]);
      setAnalysis(null);
      setBatchResults([]);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível limpar o histórico.");
    }
  }

  async function exportReport(item: Analysis) {
    setReportError("");
    setIsDownloadingReport(true);
    try {
      const { downloadSecurityReport } = await import("./services/pdfReport");
      downloadSecurityReport(item);
    } catch (cause) {
      setReportError(
        cause instanceof Error
          ? `Não foi possível gerar o relatório PDF: ${cause.message}`
          : "Não foi possível gerar o relatório PDF.",
      );
    } finally {
      setIsDownloadingReport(false);
    }
  }

  const historyScans = history.length;
  const totalFindings = history.reduce(
    (total, item) => total + findingOccurrences(item),
    0,
  );
  const currentScore = analysis ? scoreFor(analysis) : null;
  const latestScan = history[0];
  const latestSeverityCounts = latestScan?.findings.reduce(
    (total, finding) => {
      total[finding.severity] += finding.locations.length;
      return total;
    },
    { Crítica: 0, Alta: 0, Média: 0, Baixa: 0 },
  ) ?? { Crítica: 0, Alta: 0, Média: 0, Baixa: 0 };
  const latestCriticalFindings = latestSeverityCounts.Crítica + latestSeverityCounts.Alta;
  const latestRiskScore = latestScan ? scoreFor(latestScan) : null;
  const latestRiskLabel = latestRiskScore === null
    ? "Aguardando análise"
    : latestRiskScore >= 80
      ? "Boa postura"
      : latestRiskScore >= 55
        ? "Atenção necessária"
        : "Risco elevado";

  function toggleSidebar() {
    if (window.matchMedia("(max-width: 700px)").matches) {
      setSidebarOpen((open) => !open);
      return;
    }
    setSidebarCollapsed((collapsed) => !collapsed);
  }

  if (portal === "landing") {
    return (
      <MarketingPage
        theme={theme}
        onToggleTheme={() => setTheme((current) => current === "dark" ? "light" : "dark")}
        onLogin={() => { setAuthMode("login"); setPortal("auth"); }}
        onSignup={() => { setAuthMode("signup"); setPortal("auth"); }}
      />
    );
  }

  if (portal === "auth") {
    return (
      <AuthPage
        mode={authMode}
        onModeChange={setAuthMode}
        onAuthenticate={async (email, password, mode) => {
          await authenticateWithApi(mode, email, password);
          setUserEmail(email);
          setPortal("workspace");
          setError("");
        }}
        onBack={() => setPortal("landing")}
      />
    );
  }

  return (
    <div className={`app-shell ${sidebarCollapsed ? "sidebar-is-collapsed" : ""}`} id="inicio" data-theme={theme}>
      <div
        className={`sidebar-backdrop ${sidebarOpen ? "visible" : ""}`}
        onClick={() => setSidebarOpen(false)}
        aria-hidden="true"
      />
      <aside
        id="workspace-navigation"
        className={`sidebar ${sidebarOpen ? "sidebar-open" : ""} ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}
      >
        <div className="sidebar-brand">
          <Logo />
          <button
            className="icon-button sidebar-close"
            type="button"
            aria-label="Fechar menu"
            onClick={() => setSidebarOpen(false)}
          >
            <X size={18} />
          </button>
        </div>

        <span className="sidebar-label">WORKSPACE</span>
        <nav className="side-nav" aria-label="Navegação do workspace">
          <button
            type="button"
            className={`side-link ${view === "dashboard" ? "active" : ""}`}
            aria-label="Dashboard"
            title="Dashboard"
            onClick={() => setViewAndClose("dashboard")}
          >
            <Gauge size={17} />
            <span>Dashboard</span>
            <span className="nav-shortcut">⌘ 1</span>
          </button>
          <button
            type="button"
            className={`side-link ${view === "scanner" ? "active" : ""}`}
            aria-label="Scanner"
            title="Scanner"
            onClick={() => setViewAndClose("scanner")}
          >
            <ScanLine size={17} />
            <span>Scanner</span>
            <span className="nav-shortcut">⌘ 2</span>
          </button>
          <button
            type="button"
            className={`side-link ${view === "coverage" ? "active" : ""}`}
            aria-label="Cobertura OWASP"
            title="Cobertura OWASP"
            onClick={() => setViewAndClose("coverage")}
          >
            <Layers3 size={17} />
            <span>Cobertura OWASP</span>
            <span className="nav-count">10</span>
          </button>
          <button
            type="button"
            className={`side-link ${view === "history" ? "active" : ""}`}
            aria-label="Histórico"
            title="Histórico"
            onClick={() => setViewAndClose("history")}
          >
            <History size={17} />
            <span>Histórico</span>
            {historyScans > 0 && <span className="nav-count">{historyScans}</span>}
          </button>
        </nav>

        <span className="sidebar-label sidebar-label-gap">ATALHOS</span>
        <div className="side-nav">
          <button className="side-link" type="button" aria-label="Exemplo Python" title="Exemplo Python" onClick={() => useDemo("python")}>
            <Code2 size={17} />
            <span>Exemplo Python</span>
            <ArrowDown className="shortcut-arrow" size={13} />
          </button>
          <button className="side-link" type="button" aria-label="Exemplo JavaScript" title="Exemplo JavaScript" onClick={() => useDemo("javascript")}>
            <Braces size={17} />
            <span>Exemplo JavaScript</span>
            <ArrowDown className="shortcut-arrow" size={13} />
          </button>
        </div>

        <div className="sidebar-bottom">
          <div className="local-status">
            <span className="online-indicator" />
            <span>
              <strong>{apiMode ? "API conectada" : "Processamento local"}</strong>
              <small>{apiMode ? "Sessão e histórico no backend" : "Nenhum código é enviado"}</small>
            </span>
          </div>
          <button
            type="button"
            className="side-link reference-link"
            aria-label="Documentação OWASP"
            title="Documentação OWASP"
            onClick={() => setViewAndClose("coverage")}
          >
            <BookOpenCheck size={16} />
            <span>Documentação OWASP</span>
            <ArrowUpRight size={13} />
          </button>
        </div>
      </aside>

      <div className="main-shell">
        <header className="topbar">
          <div className="topbar-start">
            <button
              type="button"
              className="icon-button mobile-menu"
              aria-label={window.matchMedia("(max-width: 700px)").matches
                ? sidebarOpen ? "Fechar menu de navegação" : "Abrir menu de navegação"
                : sidebarCollapsed ? "Expandir navegação" : "Recolher navegação"}
              aria-controls="workspace-navigation"
              aria-expanded={window.matchMedia("(max-width: 700px)").matches ? sidebarOpen : !sidebarCollapsed}
              onClick={toggleSidebar}
            >
              <Menu size={19} />
            </button>
            <span className="breadcrumb-root">Workspace</span>
            <ChevronRight size={14} />
            <span className="breadcrumb-current">
              {view === "dashboard" ? "Dashboard" : view === "scanner" ? "Análise de código" : view === "coverage" ? "OWASP Top 10" : "Histórico"}
            </span>
          </div>
          <div className="topbar-end">
            <span className="stack-pill"><span /> {apiMode ? "Frontend · API conectada" : "Frontend · modo local"}</span>
            <span className="topbar-divider" />
            <span className="workspace-user-email">{userEmail}</span>
            <details className="profile-menu">
              <summary className="avatar-small profile-trigger" aria-label="Abrir opções do perfil" title={userEmail}>
                {userEmail.slice(0, 1).toUpperCase() || "VC"}
              </summary>
              <div className="profile-popover">
                <span className="profile-menu-email">{userEmail}</span>
                <ThemeToggle
                  theme={theme}
                  onToggle={() => setTheme((current) => current === "dark" ? "light" : "dark")}
                  className="profile-menu-action"
                />
                <button
                  className="profile-menu-action"
                  type="button"
                  onClick={() => { logoutFromApi(); setUserEmail(""); setPortal("landing"); }}
                >
                  <LogOut size={15} /> <span>Sair da conta</span>
                </button>
              </div>
            </details>
          </div>
        </header>

        <main className="main-content">
          {view === "dashboard" && (
            <>
              <section className="welcome-row dashboard-welcome-row">
                <div className="welcome-copy">
                  <div className="eyebrow welcome-eyebrow">
                    <span className="eyebrow-spark"><Sparkles size={12} /></span>
                    VISÃO GERAL DO WORKSPACE
                  </div>
                  <h1>
                    Segurança do código,<br />
                    <span>em um só lugar.</span>
                  </h1>
                  <p>
                    Acompanhe análises, entenda os riscos prioritários e escolha o próximo
                    passo para proteger seu projeto.
                  </p>
                  <div className="welcome-tags">
                    <span><ShieldCheck size={13} /> {apiMode ? "Dados sincronizados com a API" : "Código analisado localmente"}</span>
                    <span><Activity size={13} /> {latestScan ? `Atualizado ${new Date(latestScan.createdAt).toLocaleString("pt-BR")}` : "Pronto para a primeira análise"}</span>
                  </div>
                  <button
                    className="btn button-primary dashboard-scan-button"
                    type="button"
                    onClick={() => setView("scanner")}
                  >
                    <ScanLine size={15} /> Nova análise <ArrowRight size={14} />
                  </button>
                </div>
                <div className="welcome-visual" aria-hidden="true">
                  <div className="visual-orbit orbit-one" />
                  <div className="visual-orbit orbit-two" />
                  <div className="visual-cross cross-a" />
                  <div className="visual-cross cross-b" />
                  <div className="visual-core">
                    <div className="visual-core-inner">
                      <Gauge size={43} strokeWidth={1.3} />
                    </div>
                  </div>
                  <span className="visual-chip chip-a"><LockKeyhole size={13} /> secure</span>
                  <span className="visual-chip chip-b"><Activity size={13} /> review</span>
                  <span className="visual-glow" />
                </div>
              </section>

              <section className="metric-strip dashboard-metrics" aria-label="Indicadores de segurança">
                <div className="metric-tile">
                  <IconBadge tone="violet"><FileSearch size={17} /></IconBadge>
                  <div><span>ANÁLISES REALIZADAS</span><strong>{historyScans}</strong></div>
                  <span className="metric-caption">no histórico</span>
                </div>
                <div className="metric-tile">
                  <IconBadge tone={latestCriticalFindings > 0 ? "red" : "lime"}><ShieldAlert size={17} /></IconBadge>
                  <div><span>ACHADOS CRÍTICOS E ALTOS</span><strong>{latestCriticalFindings}</strong></div>
                  <span className="metric-caption">na última análise</span>
                </div>
                <div className="metric-tile">
                  <IconBadge tone="blue"><Code2 size={17} /></IconBadge>
                  <div><span>LINHAS ANALISADAS</span><strong>{latestScan ? latestScan.linesAnalyzed.toLocaleString("pt-BR") : "—"}</strong></div>
                  <span className="metric-caption">na última análise</span>
                </div>
                <div className="metric-tile">
                  <IconBadge tone="lime"><Gauge size={17} /></IconBadge>
                  <div><span>ÍNDICE DE SEGURANÇA</span><strong>{latestRiskScore ?? "—"}<small>{latestRiskScore !== null ? "/100" : ""}</small></strong></div>
                  <span className="metric-caption">{latestRiskLabel}</span>
                </div>
              </section>

              <section className="workspace-grid row g-3 align-items-start">
                <div className="col-12 col-xl-7">
                  <div className="workspace-card scan-card dashboard-posture-card">
                    <div className="card-heading">
                      <div>
                        <div className="eyebrow">POSTURA DE SEGURANÇA</div>
                        <h2>{latestScan ? "Resumo da última análise" : "Seu painel de segurança começa aqui"}</h2>
                        <p>{latestScan ? `${latestScan.filename} · ${new Date(latestScan.createdAt).toLocaleString("pt-BR")}` : "Faça uma análise para receber indicadores reais sobre seus arquivos."}</p>
                      </div>
                      <span className={`privacy-chip ${latestCriticalFindings > 0 ? "privacy-chip-risk" : ""}`}>
                        {latestScan ? latestRiskLabel.toUpperCase() : "SEM DADOS"}
                      </span>
                    </div>

                    {latestScan ? (
                      <>
                        <div className={`dashboard-risk-summary ${latestRiskScore !== null && latestRiskScore < 55 ? "dashboard-risk-summary-risk" : ""}`}>
                          <div className={`dashboard-score ${latestRiskScore !== null && latestRiskScore < 55 ? "dashboard-score-risk" : ""}`}>
                            <strong>{latestRiskScore}</strong><span>/100</span>
                          </div>
                          <div className="dashboard-risk-copy">
                            <strong>{latestRiskLabel}</strong>
                            <span>{findingOccurrences(latestScan)} ocorrência(s) identificada(s) em {latestScan.linesAnalyzed.toLocaleString("pt-BR")} linhas.</span>
                          </div>
                          <button className="text-link" type="button" onClick={() => { setBatchResults([]); setAnalysis(latestScan); setView("scanner"); }}>
                            Ver relatório <ArrowRight size={13} />
                          </button>
                        </div>
                        <div className="dashboard-severity-list" aria-label="Achados por severidade">
                          {([
                            ["Crítica", latestSeverityCounts.Crítica],
                            ["Alta", latestSeverityCounts.Alta],
                            ["Média", latestSeverityCounts.Média],
                            ["Baixa", latestSeverityCounts.Baixa],
                          ] as const).map(([severity, count]) => (
                            <div className="dashboard-severity-row" key={severity}>
                              <span className={`severity-dot ${severityStyle(severity)}`} />
                              <span>{severity}</span>
                              <strong>{count}</strong>
                              <div className="dashboard-severity-track">
                                <span className={severityStyle(severity)} style={{ width: `${findingOccurrences(latestScan) ? Math.max(count ? 4 : 0, count / findingOccurrences(latestScan) * 100) : 0}%` }} />
                              </div>
                            </div>
                          ))}
                        </div>
                        <p className="dashboard-score-note">O índice é heurístico e considera a quantidade e a severidade dos achados; não substitui uma auditoria de segurança.</p>
                      </>
                    ) : (
                      <div className="dashboard-empty-state">
                        <span className="dashboard-empty-icon"><ScanLine size={21} /></span>
                        <div>
                          <strong>Nenhuma análise por enquanto</strong>
                          <p>Envie um arquivo ou cole um trecho para ver vulnerabilidades, severidade e recomendações aqui.</p>
                        </div>
                        <button className="btn button-primary" type="button" onClick={() => setView("scanner")}>
                          Iniciar análise <ArrowRight size={14} />
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="col-12 col-xl-5 dashboard-side-column">
                  <div className="workspace-card scan-card dashboard-recent-card">
                    <div className="card-heading">
                      <div>
                        <div className="eyebrow">ATIVIDADE</div>
                        <h2>Análises recentes</h2>
                        <p>Seus últimos arquivos revisados.</p>
                      </div>
                      {historyScans > 0 && <button className="text-link" type="button" onClick={() => setView("history")}>Ver todas <ArrowRight size={13} /></button>}
                    </div>
                    {historyScans > 0 ? (
                      <div className="dashboard-recent-list">
                        {history.slice(0, 4).map((item) => (
                          <button
                            className="dashboard-recent-item"
                            key={item.id}
                            type="button"
                            onClick={() => { setBatchResults([]); setAnalysis(item); setView("scanner"); }}
                          >
                            <span className={`dashboard-recent-icon ${findingOccurrences(item) ? "has-findings" : ""}`}>
                              {findingOccurrences(item) ? <ShieldAlert size={15} /> : <BadgeCheck size={15} />}
                            </span>
                            <span className="dashboard-recent-meta">
                              <strong>{item.filename}</strong>
                              <small>{item.language} · {new Date(item.createdAt).toLocaleDateString("pt-BR")}</small>
                            </span>
                            <span className="dashboard-recent-result">
                              <strong>{findingOccurrences(item)}</strong>
                              <small>achados</small>
                            </span>
                            <ChevronRight size={14} />
                          </button>
                        ))}
                      </div>
                    ) : (
                      <div className="dashboard-activity-empty">
                        <Clock3 size={18} />
                        <span>As análises recentes aparecerão aqui.</span>
                      </div>
                    )}
                  </div>

                  <div className="workspace-card scan-card dashboard-integration-card">
                    <div className="card-heading">
                      <div>
                        <div className="eyebrow">AUTOMAÇÃO</div>
                        <h2>Integração com CI/CD</h2>
                      </div>
                      <span className="privacy-chip"><Activity size={12} /> MVP</span>
                    </div>
                    <div className="dashboard-integrations">
                      <div><span className="integration-status integration-status-live" /><span>GitHub Actions</span><strong>Disponível</strong></div>
                      <div><span className="integration-status" /><span>GitLab CI</span><strong>Planejado</strong></div>
                      <div><span className="integration-status" /><span>Bitbucket Pipelines</span><strong>Planejado</strong></div>
                    </div>
                    <p className="dashboard-integration-note">Comentários automáticos em Pull Requests do GitHub estão disponíveis no workflow do projeto.</p>
                  </div>
                </div>
              </section>
            </>
          )}

          {view === "scanner" && (
            <>
              <section className="welcome-row">
                <div className="welcome-copy">
                  <div className="eyebrow welcome-eyebrow">
                    <span className="eyebrow-spark"><Sparkles size={12} /></span>
                    APPLICATION SECURITY WORKSPACE
                  </div>
                  <h1>
                    Código melhor.<br />
                    <span>Menos risco.</span>
                  </h1>
                  <p>
                    Encontre sinais de vulnerabilidade, entenda o impacto e saia
                    daqui com um plano de correção.
                  </p>
                  <div className="welcome-tags">
                    <span><ShieldCheck size={13} /> Análise privada no navegador</span>
                    <span><Zap size={13} /> {analysis?.rulesRun ?? 21} verificações ativas</span>
                  </div>
                </div>
                <div className="welcome-visual" aria-hidden="true">
                  <div className="visual-orbit orbit-one" />
                  <div className="visual-orbit orbit-two" />
                  <div className="visual-cross cross-a" />
                  <div className="visual-cross cross-b" />
                  <div className="visual-core">
                    <div className="visual-core-inner">
                      <ShieldCheck size={43} strokeWidth={1.3} />
                    </div>
                  </div>
                  <span className="visual-chip chip-a"><LockKeyhole size={13} /> secure</span>
                  <span className="visual-chip chip-b"><Activity size={13} /> scanning</span>
                  <span className="visual-glow" />
                </div>
              </section>

              <section className="metric-strip" aria-label="Resumo local">
                <div className="metric-tile">
                  <IconBadge tone="violet"><FileSearch size={17} /></IconBadge>
                  <div><span>ANÁLISES NESTE NAVEGADOR</span><strong>{historyScans}</strong></div>
                  <span className="metric-caption">histórico local</span>
                </div>
                <div className="metric-tile">
                  <IconBadge tone="red"><ShieldAlert size={17} /></IconBadge>
                  <div><span>ACHADOS REGISTRADOS</span><strong>{totalFindings}</strong></div>
                  <span className="metric-caption">todas as análises</span>
                </div>
                <div className="metric-tile">
                  <IconBadge tone="lime"><Gauge size={17} /></IconBadge>
                  <div><span>ÚLTIMO ÍNDICE</span><strong>{latestScan ? scoreFor(latestScan) : "—"}<small>{latestScan ? "/100" : ""}</small></strong></div>
                  <span className="metric-caption">{latestScan ? latestScan.filename : "aguardando primeira análise"}</span>
                </div>
              </section>

              <section className="workspace-grid row g-3 align-items-start">
                <div className="col-12 col-xl-8">
                <div className="workspace-card scan-card">
                  <div className="card-heading">
                    <div>
                      <div className="eyebrow">NOVO SCAN</div>
                      <h2>Vamos dar uma olhada no código?</h2>
                      <p>Escolha um arquivo ou cole o trecho que quer revisar.</p>
                    </div>
                    <span className="privacy-chip"><LockKeyhole size={12} /> PRIVADO</span>
                  </div>

                  <div className="input-tabs" role="tablist" aria-label="Origem do código">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={mode === "file"}
                      className={mode === "file" ? "selected" : ""}
                      onClick={() => setMode("file")}
                    >
                      <Upload size={15} /> Enviar arquivo
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={mode === "paste"}
                      className={mode === "paste" ? "selected" : ""}
                      onClick={() => setMode("paste")}
                    >
                      <Code2 size={15} /> Colar código
                    </button>
                    <span className="input-limit">1 MB / ARQUIVO</span>
                  </div>

                  <form onSubmit={runAnalysis}>
                    {mode === "file" ? (
                      <div
                        className={`dropzone ${dragging ? "drag-active" : ""} ${filename ? "file-loaded" : ""}`}
                        onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
                        onDragOver={(event) => event.preventDefault()}
                        onDragLeave={(event) => {
                          if (event.currentTarget === event.target) setDragging(false);
                        }}
                        onDrop={handleDrop}
                      >
                        <input
                          ref={fileInput}
                          className="file-input-hidden"
                          type="file"
                          multiple
                          accept=".py,.js,.jsx,.ts,.tsx,.json,.txt,.php,.java,.go,.rb,.cs,.c,.cpp,.html,.sql,.yml,.yaml"
                          onChange={handleFileChange}
                          aria-label="Selecionar arquivos de código"
                        />
                        {selectedFiles.length ? (
                          <div className="loaded-files">
                            <div className="loaded-files-heading">
                              <strong>{selectedFiles.length} arquivo(s) selecionado(s)</strong>
                              <button className="browse-button" type="button" onClick={() => fileInput.current?.click()}>Substituir seleção</button>
                            </div>
                            {selectedFiles.map((file, index) => (
                              <div className="loaded-file" key={`${file.filename}-${index}`}>
                                <div className="loaded-file-icon"><FileCode2 size={18} /></div>
                                <div className="loaded-file-copy">
                                  <strong>{file.filename}</strong>
                                  <span>{file.source.split(/\r?\n/).length.toLocaleString("pt-BR")} linhas · pronto para análise</span>
                                </div>
                                <button
                                  type="button"
                                  className="icon-button remove-file"
                                  aria-label={`Remover ${file.filename}`}
                                  onClick={() => {
                                    const remaining = selectedFiles.filter((_, fileIndex) => fileIndex !== index);
                                    setSelectedFiles(remaining);
                                    setFilename(remaining[0]?.filename ?? "");
                                    setSource(remaining[0]?.source ?? "");
                                    setAnalysis(null);
                                    setBatchResults([]);
                                  }}
                                >
                                  <X size={16} />
                                </button>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <>
                            <div className="upload-icon"><Upload size={22} /></div>
                            <strong>Arraste seus arquivos até aqui</strong>
                            <span>ou <button className="browse-button" type="button" onClick={() => fileInput.current?.click()}>escolha no computador</button></span>
                            <small>Até {MAX_BATCH_FILES} arquivos · limite de 1 MB por arquivo</small>
                          </>
                        )}
                      </div>
                    ) : (
                      <div className="code-editor">
                        <div className="editor-topbar">
                          <div className="editor-dots"><i /><i /><i /></div>
                          <input
                            className="filename-input"
                            aria-label="Nome do arquivo"
                            value={filename}
                            onChange={(event) => setFilename(event.target.value)}
                            placeholder="nome-do-arquivo.py"
                            maxLength={120}
                          />
                          <span className="editor-language">{filename.split(".").pop()?.toUpperCase() || "CODE"}</span>
                        </div>
                        <div className="editor-body">
                          <div className="line-gutter" aria-hidden="true">
                            {Array.from({ length: Math.max(10, source.split(/\r?\n/).length) }, (_, index) => (
                              <span key={index}>{index + 1}</span>
                            ))}
                          </div>
                          <textarea
                            value={source}
                            onChange={(event) => setSource(event.target.value)}
                            placeholder={"# Cole seu código aqui\n\n# Você também pode carregar um dos exemplos vulneráveis"}
                            aria-label="Código fonte para análise"
                            spellCheck={false}
                            maxLength={1_000_000}
                          />
                        </div>
                        <div className="editor-footer">
                          <span><span className="editor-live-dot" /> LOCAL · NENHUM ENVIO</span>
                          <span>{source.length.toLocaleString("pt-BR")} / 1.000.000 caracteres</span>
                        </div>
                      </div>
                    )}

                    {error && <div className="error-notice" role="alert"><AlertTriangle size={15} /> {error}</div>}

                    <div className="scan-controls">
                      <span className="scan-note"><Shield size={14} /> {apiMode ? "Código enviado à API configurada." : "Seu código permanece neste dispositivo."}</span>
                      <button className="btn button-primary scan-button" type="submit" disabled={isScanning}>
                        {isScanning ? <><RefreshCw size={16} className="spin" /> Analisando</> : <><ScanLine size={16} /> Iniciar análise <ArrowRight size={15} /></>}
                      </button>
                    </div>
                  </form>

                  <div className="demo-divider"><span>OU EXPERIMENTE COM UM EXEMPLO</span></div>
                  <div className="demo-buttons">
                    <button type="button" onClick={() => useDemo("python")}><span className="language-icon python-icon">Py</span> Exemplo Python <ArrowUpRight size={13} /></button>
                    <button type="button" onClick={() => useDemo("javascript")}><span className="language-icon js-icon">JS</span> Exemplo JavaScript <ArrowUpRight size={13} /></button>
                  </div>
                </div>

                </div>
                <div className="col-12 col-xl-4">
                <aside className="side-insights">
                  <div className="insight-card score-card">
                    <div className="insight-heading"><span>POSTURA DE SEGURANÇA</span><Activity size={15} /></div>
                    <div className="score-display">
                      <div className={`score-ring ${latestScan && scoreFor(latestScan) < 50 ? "score-risk" : ""}`}>
                        <span>{latestScan ? scoreFor(latestScan) : "—"}</span>
                        {latestScan && <small>/100</small>}
                      </div>
                      <div className="score-explainer">
                        <strong>{latestScan ? "Último resultado" : "Pronto para começar"}</strong>
                        <span>{latestScan ? `${findingOccurrences(latestScan)} achado(s) detectado(s)` : "Sua análise aparecerá aqui"}</span>
                      </div>
                    </div>
                    <div className="mini-meter"><span style={{ width: `${latestScan ? scoreFor(latestScan) : 0}%` }} /></div>
                    <div className="score-range"><span>RISCO ALTO</span><span>MAIS SEGURO</span></div>
                  </div>

                  <div className="insight-card quick-card">
                    <div className="insight-heading"><span>BASE DE VERIFICAÇÃO</span><Radar size={15} /></div>
                    <div className="quick-rule-list">
                      <div><span className="quick-icon"><Bug size={14} /></span><span>Injeção e execução</span><Check size={14} /></div>
                      <div><span className="quick-icon"><LockKeyhole size={14} /></span><span>Segredos e autenticação</span><Check size={14} /></div>
                      <div><span className="quick-icon"><Layers3 size={14} /></span><span>OWASP Top 10:2025</span><Check size={14} /></div>
                    </div>
                    <button className="text-link" type="button" onClick={() => setView("coverage")}>Ver mapa OWASP completo <ArrowRight size={13} /></button>
                  </div>

                  <div className="privacy-note">
                    <span className="privacy-note-icon"><LockKeyhole size={15} /></span>
                    <p><strong>Privacidade primeiro</strong><br />{apiMode ? "O código é enviado à API configurada para análise." : "O código é analisado no navegador e não é enviado a nenhum servidor."}</p>
                  </div>
                </aside>
                </div>
              </section>

              {isScanning && (
                <section className="scan-progress-card" aria-live="polite">
                  <div className="progress-main">
                    <div className="progress-orb"><Radar size={22} /></div>
                    <div className="progress-copy">
                      <span className="eyebrow">ANÁLISE EM ANDAMENTO</span>
                      <h3>{batchProgress ? `Analisando arquivo ${batchProgress.current} de ${batchProgress.total}` : scanStages[Math.max(stage, 0)].title}</h3>
                      <p>{batchProgress ? batchProgress.filename : scanStages[Math.max(stage, 0)].detail}</p>
                    </div>
                    <span className="progress-percent">
                      {batchProgress
                        ? `${Math.min(96, Math.round(((batchProgress.current - 1 + (stage + 1) / 4) / batchProgress.total) * 100))}%`
                        : `${Math.min(96, (stage + 1) * 24)}%`}
                    </span>
                  </div>
                  <div className="progress-track"><span style={{ width: batchProgress ? `${Math.min(96, Math.round(((batchProgress.current - 1 + (stage + 1) / 4) / batchProgress.total) * 100))}%` : `${Math.min(96, (stage + 1) * 24)}%` }} /></div>
                  <div className="progress-steps">
                    {scanStages.map((scanStage, index) => {
                      const StageIcon = scanStage.icon;
                      return (
                        <span className={index < stage ? "stage-complete" : index === stage ? "stage-current" : ""} key={scanStage.title}>
                          {index < stage ? <Check size={13} /> : <StageIcon size={13} />}
                          {scanStage.title}
                        </span>
                      );
                    })}
                  </div>
                </section>
              )}

              {analysis && (
                <section className="results-section" ref={resultsRef}>
                  <div className="results-heading">
                    <div>
                      <div className="eyebrow"><span className="results-pulse" /> SCAN CONCLUÍDO · {analysis.durationMs} MS</div>
                      <h2>Relatório de análise</h2>
                      <p>{analysis.filename} <span>·</span> {analysis.linesAnalyzed.toLocaleString("pt-BR")} linhas <span>·</span> {analysis.language}</p>
                    </div>
                    <button className="btn button-primary pdf-button" type="button" disabled={isDownloadingReport} onClick={() => void exportReport(analysis)}>
                      {isDownloadingReport ? <RefreshCw size={16} className="spin" /> : <FileDown size={16} />}
                      {isDownloadingReport ? "Gerando relatório..." : "Baixar relatório PDF"}
                    </button>
                  </div>
                  {reportError && <div className="error-notice" role="alert"><AlertTriangle size={15} /> {reportError}</div>}
                  {batchResults.length > 1 && (
                    <div className="batch-results" aria-label="Resultados por arquivo">
                      <span>{batchResults.length} arquivos analisados</span>
                      <div className="batch-result-tabs" role="tablist" aria-label="Selecionar relatório do arquivo">
                        {batchResults.map((item) => (
                          <button
                            type="button"
                            role="tab"
                            aria-selected={analysis.id === item.id}
                            className={analysis.id === item.id ? "selected" : ""}
                            key={item.id}
                            onClick={() => {
                              setAnalysis(item);
                              setFilter("Todas");
                              setOwaspCategoryFilter(null);
                            }}
                          >
                            <FileCode2 size={13} /> {item.filename}
                            <span>{findingOccurrences(item)} achado(s)</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="result-kpis">
                    <div className="result-kpi result-total"><span>ACHADOS</span><strong>{counts.occurrences}</strong><small>{analysis.findings.length} categorias</small></div>
                    <div className="result-kpi result-critical"><span>CRÍTICOS</span><strong>{counts.critical}</strong><small>correção imediata</small></div>
                    <div className="result-kpi result-high"><span>ALTOS</span><strong>{counts.high}</strong><small>prioridade alta</small></div>
                    <div className="result-kpi result-score"><span>ÍNDICE</span><strong>{currentScore}<small>/100</small></strong><small>heurística demonstrativa</small></div>
                  </div>
                  <div className="findings-panel">
                    <div className="findings-toolbar">
                      <div>
                        <h3>Achados prioritários</h3>
                        <span>
                          {activeOwaspCategory
                            ? `Filtrado por ${activeOwaspCategory.id}: ${activeOwaspCategory.title}`
                            : `${counts.occurrences} ocorrência(s) em ${analysis.findings.length} categoria(s)`}
                        </span>
                        {activeOwaspCategory && (
                          <button
                            className="clear-owasp-filter"
                            type="button"
                            onClick={() => setOwaspCategoryFilter(null)}
                          >
                            Limpar filtro <X size={11} />
                          </button>
                        )}
                      </div>
                      <div className="filter-tabs" aria-label="Filtrar por severidade">
                        {["Todas", "Crítica", "Alta", "Média"].map((severity) => (
                          <button className={filter === severity ? "active" : ""} type="button" key={severity} onClick={() => setFilter(severity)}>
                            {severity}{severity === "Todas" ? ` · ${analysis.findings.length}` : ""}
                          </button>
                        ))}
                      </div>
                    </div>
                    {analysis.findings.length ? (
                      <div className="finding-list">
                        {filteredFindings.map((finding) => (
                          <FindingRow finding={finding} filename={analysis.filename} key={finding.id} />
                        ))}
                        {filteredFindings.length === 0 && <div className="no-findings">Nenhum achado com essa severidade.</div>}
                      </div>
                    ) : (
                      <div className="clean-result"><BadgeCheck size={29} /><strong>Nenhum padrão sinalizado</strong><span>As regras desta versão não encontraram correspondências. Isso não comprova que o código esteja livre de vulnerabilidades.</span></div>
                    )}
                    <div className="findings-footer"><AlertTriangle size={14} /> Resultados heurísticos — confirme cada achado no contexto do projeto.</div>
                  </div>
                  <div className="owasp-mini-map">
                    <div><div className="eyebrow">REFERÊNCIA DE SEGURANÇA</div><h3>Como os achados se conectam ao OWASP</h3><p>Veja a classificação completa e o que cada categoria pode ou não verificar automaticamente.</p></div>
                    <button className="btn button-secondary" type="button" onClick={() => setView("coverage")}>Abrir mapa OWASP <ArrowRight size={14} /></button>
                    <div className="mini-category-row">
                      {owaspCategories.map((category) => {
                        const hasFinding = analysis.findings.some((finding) => finding.owaspId === category.id);
                        return <span className={hasFinding ? "category-flagged" : ""} key={category.id} title={`${category.id}:2025 · ${category.title}`}>{category.id}</span>;
                      })}
                    </div>
                  </div>
                </section>
              )}
            </>
          )}

          {view === "coverage" && (
            <OwaspPanel
              findings={analysis?.findings ?? []}
              hasAnalysis={analysis !== null}
              onBack={() => {
                setOwaspCategoryFilter(null);
                setView("scanner");
              }}
              onViewFindings={(categoryId) => {
                setOwaspCategoryFilter(categoryId);
                setFilter("Todas");
                setView("scanner");
                window.setTimeout(
                  () => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }),
                  120,
                );
              }}
            />
          )}

          {view === "history" && (
            <section className="workspace-card history-section">
              <div className="section-heading-row">
                <div>
                  <div className="eyebrow">SEUS DADOS, NESTE DISPOSITIVO</div>
                  <h2>Histórico de análises</h2>
                  <p>As análises são armazenadas localmente neste navegador.</p>
                </div>
                {history.length > 0 && <button className="btn button-secondary danger-button" type="button" onClick={() => void clearHistory()}><X size={14} /> Limpar histórico</button>}
              </div>
              {error && <div className="error-notice" role="alert"><AlertTriangle size={15} /> {error}</div>}
              {reportError && <div className="error-notice" role="alert"><AlertTriangle size={15} /> {reportError}</div>}
              {!historyLoaded ? (
                <div className="history-empty"><RefreshCw className="spin" size={20} /><span>Carregando seu histórico...</span></div>
              ) : history.length ? (
                <div className="history-list">
                  {history.map((item) => (
                    <article className="history-item" key={item.id}>
                      <IconBadge tone={findingOccurrences(item) ? "red" : "lime"}>{findingOccurrences(item) ? <ShieldAlert size={17} /> : <ShieldCheck size={17} />}</IconBadge>
                      <div className="history-item-main">
                        <strong>{item.filename}</strong>
                        <span>{item.language} <i /> {new Date(item.createdAt).toLocaleString("pt-BR")} <i /> {item.linesAnalyzed.toLocaleString("pt-BR")} linhas</span>
                      </div>
                      <span className="history-findings">{findingOccurrences(item)} achados</span>
                      <button className="text-link" type="button" onClick={() => { setBatchResults([]); setAnalysis(item); setView("scanner"); setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth" }), 80); }}>Ver relatório <ArrowRight size={13} /></button>
                      <button className="icon-button history-download" aria-label={`Baixar relatório de ${item.filename}`} disabled={isDownloadingReport} type="button" onClick={() => void exportReport(item)}>{isDownloadingReport ? <RefreshCw size={15} className="spin" /> : <FileDown size={16} />}</button>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="history-empty">
                  <div className="history-empty-icon"><Clock3 size={22} /></div>
                  <strong>Seu histórico começa aqui</strong>
                  <span>Quando você fizer uma análise, os resultados aparecerão nesta lista.</span>
                  <button className="btn button-primary" type="button" onClick={() => setView("scanner")}>Fazer primeira análise <ArrowRight size={14} /></button>
                </div>
              )}
            </section>
          )}

          <footer className="app-footer">
            <span><Logo /> <span className="footer-copy">Security clarity for every commit.</span></span>
            <span>Frontend demonstrativo · <a href="https://top10.owasp.org/2025/" target="_blank" rel="noreferrer">OWASP Top 10:2025</a> <ArrowUpRight size={12} /></span>
          </footer>
        </main>
      </div>
    </div>
  );
}

export default App;
