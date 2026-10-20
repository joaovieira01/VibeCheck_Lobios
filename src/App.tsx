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
  History,
  KeyRound,
  Layers3,
  LockKeyhole,
  Mail,
  Menu,
  MoveRight,
  ShieldCheck,
  Radar,
  RefreshCw,
  ScanLine,
  Shield,
  ShieldAlert,
  Sparkles,
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
import { analysisService } from "./services/analysisService";
import type { Analysis, Finding } from "./types";

type View = "scanner" | "coverage" | "history";
type InputMode = "paste" | "file";

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
  onBack,
}: {
  findings: Finding[];
  onBack: () => void;
}) {
  const categoryCounts = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((finding) => {
      counts.set(
        finding.owaspId,
        (counts.get(finding.owaspId) ?? 0) + finding.locations.length,
      );
    });
    return counts;
  }, [findings]);

  return (
    <section className="workspace-card coverage-section">
      <div className="section-heading-row">
        <div>
          <div className="eyebrow">MAPA DE REFERÊNCIA</div>
          <h2>OWASP Top 10 <span className="heading-year">2025</span></h2>
          <p>
            Uma base de orientação, não um certificado de cobertura. Cada categoria
            precisa ser avaliada no contexto do sistema.
          </p>
        </div>
        <button className="btn button-secondary" onClick={onBack} type="button">
          Voltar ao scanner <ArrowRight size={15} />
        </button>
      </div>
      <div className="owasp-grid row row-cols-1 row-cols-md-2 g-2">
        {owaspCategories.map((category) => {
          const count = categoryCounts.get(category.id) ?? 0;
          return (
            <div className="col" key={category.id}>
              <a
                className={`owasp-card h-100 ${count ? "has-findings" : ""}`}
                href={category.url}
                target="_blank"
                rel="noreferrer"
              >
                <div className="owasp-card-top">
                  <span className="owasp-id">{category.id}</span>
                  <span className={`owasp-status ${count ? "flagged" : "review"}`}>
                    {count ? `${count} sinal(is)` : "revisar"}
                  </span>
                </div>
                <h3>{category.title}</h3>
                <p>{category.guidance}</p>
                <span className="owasp-card-bottom">
                  {category.automated ? "Heurísticas + revisão contextual" : "Revisão manual"}
                  <ArrowUpRight size={13} />
                </span>
              </a>
            </div>
          );
        })}
      </div>
      <div className="coverage-footnote">
        <AlertTriangle size={15} />
        “Sem sinal” significa apenas que as regras atuais não encontraram um
        padrão correspondente. Não significa que a aplicação esteja segura.
      </div>
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
    </section>
  );
}

function MarketingPage({
  onLogin,
  onSignup,
}: {
  onLogin: () => void;
  onSignup: () => void;
}) {
  return (
    <div className="marketing-shell">
      <header className="marketing-nav">
        <Logo />
        <nav aria-label="Navegação principal">
          <a href="#recursos">Recursos</a>
          <a href="#como-funciona">Como funciona</a>
          <a href="#cobertura">Cobertura</a>
        </nav>
        <div className="marketing-nav-actions">
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
              <span><LockKeyhole size={14} /> Código processado localmente</span>
              <span><ShieldCheck size={14} /> Sem backend nesta demonstração</span>
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
          <div><strong>0</strong><span>envios ao servidor</span></div>
          <i />
          <div><strong>1 MB</strong><span>limite por arquivo</span></div>
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
              <h3>Uma revisão rápida, no seu navegador.</h3>
              <p>Envie um arquivo de texto ou cole código. A demonstração executa regras heurísticas locais e não envia seu conteúdo a um servidor.</p>
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

        <section className="marketing-process" id="como-funciona">
          <div className="process-copy">
            <span className="eyebrow">SIMPLES, TRANSPARENTE, LOCAL</span>
            <h2>Segurança com<br /><span>clareza em cada etapa.</span></h2>
            <p>
              Um protótipo para demonstrar a experiência. O serviço está isolado
              por uma interface e pode ser substituído por uma API quando o
              backend estiver pronto.
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
        <span>Protótipo frontend demonstrativo · Sem autenticação ou análise de produção</span>
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
  onAuthenticate: (email: string) => void;
  onBack: () => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const isSignup = mode === "signup";

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setNotice("");
    if (mode === "reset") {
      setNotice("Demonstração local: nenhum e-mail foi enviado. O backend de recuperação ainda não está conectado.");
      return;
    }
    if (mode === "login" && (email.trim().toLowerCase() !== "demo@vibecheck.dev" || password !== "vibecheck2026")) {
      setError("Acesso de demonstração: use demo@vibecheck.dev e a senha vibecheck2026.");
      return;
    }
    if (password.length < 8) {
      setError("Use uma senha demonstrativa com pelo menos 8 caracteres.");
      return;
    }
    onAuthenticate(email.trim());
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
          <span className="eyebrow"><span className="online-indicator" /> AMBIENTE DE DEMONSTRAÇÃO</span>
          <h1>Segurança começa<br />com <span>visibilidade.</span></h1>
          <p>Entre no workspace local para experimentar a análise, explorar os achados e gerar um relatório demonstrativo.</p>
          <div className="auth-story-list">
            <span><CheckCircle2 size={15} /> Código permanece no navegador</span>
            <span><CheckCircle2 size={15} /> Sem servidor ou conta real</span>
            <span><CheckCircle2 size={15} /> Dados limitados a esta sessão</span>
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
          <div className="auth-card-brand"><Logo /><span className="auth-local-badge"><i /> LOCAL DEMO</span></div>
          <div className="auth-card-heading">
            <span className="eyebrow">{mode === "reset" ? "RECUPERAÇÃO DEMONSTRATIVA" : isSignup ? "CRIE UM ACESSO DE TESTE" : "BEM-VINDO DE VOLTA"}</span>
            <h2 id="auth-title">{mode === "reset" ? "Recuperar acesso" : isSignup ? "Vamos começar." : "Entre no workspace."}</h2>
            <p>{mode === "reset" ? "Teste a interface de recuperação — nenhum e-mail será enviado." : isSignup ? "O cadastro é fictício e existe apenas nesta sessão." : "Use a conta de demonstração para explorar o protótipo."}</p>
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
              {mode === "reset" ? "Simular recuperação" : isSignup ? "Criar sessão demonstrativa" : "Entrar na demonstração"}
              <ArrowRight size={15} />
            </button>
          </form>
          {mode === "login" && (
            <div className="demo-credentials">
              <span className="eyebrow">CREDENCIAIS DE TESTE</span>
              <span><Mail size={13} /> demo@vibecheck.dev</span>
              <span><KeyRound size={13} /> vibecheck2026</span>
            </div>
          )}
          <div className="auth-mode-switch">
            {mode === "reset" ? (
              <button type="button" onClick={() => { setNotice(""); onModeChange("login"); }}>Voltar ao login</button>
            ) : isSignup ? (
              <span>Já tem acesso? <button type="button" onClick={() => { setError(""); onModeChange("login"); }}>Entrar</button></span>
            ) : (
              <span>Novo por aqui? <button type="button" onClick={() => { setError(""); onModeChange("signup"); }}>Criar acesso demonstrativo</button></span>
            )}
          </div>
          <div className="auth-disclaimer"><LockKeyhole size={13} /> Protótipo sem autenticação real. Não use uma senha pessoal.</div>
        </section>
      </div>
      <footer className="auth-footer"><span>VIBECHECK · FRONTEND DEMONSTRATIVO</span><a href="https://top10.owasp.org/2025/" target="_blank" rel="noreferrer">OWASP Top 10:2025 <ArrowUpRight size={12} /></a></footer>
    </main>
  );
}

function App() {
  const [portal, setPortal] = useState<"landing" | "auth" | "workspace">("landing");
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [userEmail, setUserEmail] = useState("");
  const [view, setView] = useState<View>("scanner");
  const [mode, setMode] = useState<InputMode>("file");
  const [source, setSource] = useState("");
  const [filename, setFilename] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [history, setHistory] = useState<Analysis[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [stage, setStage] = useState(-1);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [filter, setFilter] = useState("Todas");
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
    if (filter === "Todas") return analysis.findings;
    return analysis.findings.filter((finding) => finding.severity === filter);
  }, [analysis, filter]);

  function setViewAndClose(nextView: View) {
    setView(nextView);
    setSidebarOpen(false);
    setError("");
  }

  async function loadFile(file: File | undefined) {
    if (!file) return;
    if (file.size > 1_000_000) {
      setError("O arquivo excede o limite de 1 MB. Escolha um arquivo menor.");
      return;
    }
    try {
      setFilename(file.name);
      setSource(await file.text());
      setMode("file");
      setAnalysis(null);
      setError("");
    } catch {
      setError("Não foi possível ler o arquivo. Verifique se ele está em texto UTF-8.");
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    void loadFile(event.target.files?.[0]);
    event.target.value = "";
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    void loadFile(event.dataTransfer.files?.[0]);
  }

  async function runAnalysis(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = mode === "file" ? filename : filename || "codigo-colado.txt";
    if (!source.trim()) {
      setError(mode === "file" ? "Escolha um arquivo para iniciar." : "Cole o código que deseja analisar.");
      return;
    }
    if (new Blob([source]).size > 1_000_000) {
      setError("O código excede o limite de 1 MB.");
      return;
    }

    setError("");
    setAnalysis(null);
    setIsScanning(true);
    setStage(0);
    const wait = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));
    try {
      await wait(260);
      setStage(1);
      await wait(340);
      setStage(2);
      await wait(300);
      const result = await analysisService.analyze({ filename: name, source });
      setStage(3);
      await wait(240);
      setAnalysis(result);
      setFilter("Todas");
      await reloadHistory();
      window.setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }),
        120,
      );
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Não foi possível analisar este conteúdo.",
      );
      setStage(-1);
    } finally {
      setIsScanning(false);
    }
  }

  function useDemo(which: keyof typeof demoSources) {
    const demo = demoSources[which];
    setFilename(demo.filename);
    setSource(demo.source);
    setMode("paste");
    setAnalysis(null);
    setError("");
    setView("scanner");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function clearHistory() {
    try {
      await analysisService.clearHistory();
      setHistory([]);
      setAnalysis(null);
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

  if (portal === "landing") {
    return (
      <MarketingPage
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
        onAuthenticate={(email) => { setUserEmail(email); setPortal("workspace"); setError(""); }}
        onBack={() => setPortal("landing")}
      />
    );
  }

  return (
    <div className="app-shell" id="inicio">
      <div
        className={`sidebar-backdrop ${sidebarOpen ? "visible" : ""}`}
        onClick={() => setSidebarOpen(false)}
        aria-hidden="true"
      />
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
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

        <div className="workspace-switcher">
          <div className="workspace-avatar">L</div>
          <div className="workspace-meta">
            <strong>Workspace pessoal</strong>
            <span>Plano de demonstração</span>
          </div>
          <ChevronDown size={15} />
        </div>

        <span className="sidebar-label">WORKSPACE</span>
        <nav className="side-nav" aria-label="Navegação do workspace">
          <button
            type="button"
            className={`side-link ${view === "scanner" ? "active" : ""}`}
            onClick={() => setViewAndClose("scanner")}
          >
            <ScanLine size={17} />
            <span>Scanner</span>
            <span className="nav-shortcut">⌘ 1</span>
          </button>
          <button
            type="button"
            className={`side-link ${view === "coverage" ? "active" : ""}`}
            onClick={() => setViewAndClose("coverage")}
          >
            <Layers3 size={17} />
            <span>Cobertura OWASP</span>
            <span className="nav-count">10</span>
          </button>
          <button
            type="button"
            className={`side-link ${view === "history" ? "active" : ""}`}
            onClick={() => setViewAndClose("history")}
          >
            <History size={17} />
            <span>Histórico</span>
            {historyScans > 0 && <span className="nav-count">{historyScans}</span>}
          </button>
        </nav>

        <span className="sidebar-label sidebar-label-gap">ATALHOS</span>
        <div className="side-nav">
          <button className="side-link" type="button" onClick={() => useDemo("python")}>
            <Code2 size={17} />
            <span>Exemplo Python</span>
            <ArrowDown className="shortcut-arrow" size={13} />
          </button>
          <button className="side-link" type="button" onClick={() => useDemo("javascript")}>
            <Braces size={17} />
            <span>Exemplo JavaScript</span>
            <ArrowDown className="shortcut-arrow" size={13} />
          </button>
        </div>

        <div className="sidebar-bottom">
          <div className="local-status">
            <span className="online-indicator" />
            <span>
              <strong>Processamento local</strong>
              <small>Nenhum código é enviado</small>
            </span>
          </div>
          <button
            type="button"
            className="side-link reference-link"
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
              aria-label="Abrir menu"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu size={19} />
            </button>
            <span className="breadcrumb-root">Workspace</span>
            <ChevronRight size={14} />
            <span className="breadcrumb-current">
              {view === "scanner" ? "Análise de código" : view === "coverage" ? "OWASP Top 10" : "Histórico"}
            </span>
          </div>
          <div className="topbar-end">
            <span className="stack-pill"><span /> Frontend · modo local</span>
            <span className="topbar-divider" />
            <span className="workspace-user-email">{userEmail}</span>
            <button className="avatar-small logout-avatar" type="button" aria-label="Sair da demonstração" title="Sair da demonstração" onClick={() => { setUserEmail(""); setPortal("landing"); }}>
              {userEmail.slice(0, 1).toUpperCase() || "VC"}
            </button>
          </div>
        </header>

        <main className="main-content">
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
                    <span className="input-limit">LIMITE 1 MB</span>
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
                          accept=".py,.js,.jsx,.ts,.tsx,.json,.txt,.php,.java,.go,.rb,.cs,.c,.cpp,.html,.sql,.yml,.yaml"
                          onChange={handleFileChange}
                          aria-label="Selecionar arquivo de código"
                        />
                        {filename ? (
                          <div className="loaded-file">
                            <div className="loaded-file-icon"><FileCode2 size={21} /></div>
                            <div className="loaded-file-copy">
                              <strong>{filename}</strong>
                              <span>{source.split(/\r?\n/).length.toLocaleString("pt-BR")} linhas · conteúdo pronto para análise</span>
                            </div>
                            <button
                              type="button"
                              className="icon-button remove-file"
                              aria-label="Remover arquivo selecionado"
                              onClick={() => { setFilename(""); setSource(""); setAnalysis(null); }}
                            >
                              <X size={16} />
                            </button>
                          </div>
                        ) : (
                          <>
                            <div className="upload-icon"><Upload size={22} /></div>
                            <strong>Arraste seu arquivo até aqui</strong>
                            <span>ou <button className="browse-button" type="button" onClick={() => fileInput.current?.click()}>escolha no computador</button></span>
                            <small>Python, JavaScript, TypeScript, JSON e mais</small>
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
                      <span className="scan-note"><Shield size={14} /> Seu código permanece neste dispositivo.</span>
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
                    <p><strong>Privacidade primeiro</strong><br />Nesta versão, o código é analisado no navegador e não é enviado a nenhum servidor.</p>
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
                      <h3>{scanStages[Math.max(stage, 0)].title}</h3>
                      <p>{scanStages[Math.max(stage, 0)].detail}</p>
                    </div>
                    <span className="progress-percent">{Math.min(96, (stage + 1) * 24)}%</span>
                  </div>
                  <div className="progress-track"><span style={{ width: `${Math.min(96, (stage + 1) * 24)}%` }} /></div>
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
                  <div className="result-kpis">
                    <div className="result-kpi result-total"><span>ACHADOS</span><strong>{counts.occurrences}</strong><small>{analysis.findings.length} categorias</small></div>
                    <div className="result-kpi result-critical"><span>CRÍTICOS</span><strong>{counts.critical}</strong><small>correção imediata</small></div>
                    <div className="result-kpi result-high"><span>ALTOS</span><strong>{counts.high}</strong><small>prioridade alta</small></div>
                    <div className="result-kpi result-score"><span>ÍNDICE</span><strong>{currentScore}<small>/100</small></strong><small>heurística demonstrativa</small></div>
                  </div>
                  <div className="findings-panel">
                    <div className="findings-toolbar">
                      <div><h3>Achados prioritários</h3><span>{counts.occurrences} ocorrência(s) em {analysis.findings.length} categoria(s)</span></div>
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
            <OwaspPanel findings={analysis?.findings ?? []} onBack={() => setView("scanner")} />
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
                      <button className="text-link" type="button" onClick={() => { setAnalysis(item); setView("scanner"); setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth" }), 80); }}>Ver relatório <ArrowRight size={13} /></button>
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
