function setActiveNav() {
  const page = document.body.dataset.page;
  document
    .querySelectorAll("[data-nav]")
    .forEach((a) => a.classList.toggle("active", a.dataset.nav === page));
}
setActiveNav();

const scanData = [
  {
    sev: "CRÍTICO",
    cls: "c",
    title: "SQL Injection",
    loc: "api/users.js:34",
    desc: "Entrada controlada pelo usuário foi usada diretamente na query.",
    fix: "Use prepared statements / parâmetros para separar dados de instruções SQL.",
  },
  {
    sev: "ALTO",
    cls: "a",
    title: "Cross-Site Scripting (XSS)",
    loc: "components/Search.tsx:12",
    desc: "Conteúdo foi renderizado sem sanitização adequada.",
    fix: "Sanitize entradas e evite renderização de HTML bruto quando ela não for necessária.",
  },
  {
    sev: "ALTO",
    cls: "a",
    title: "JWT sem validação de algoritmo",
    loc: "middleware/auth.js:8",
    desc: "A verificação do token não explicita o conjunto de algoritmos aceitos.",
    fix: "Defina explicitamente os algoritmos permitidos durante a verificação.",
  },
  {
    sev: "MÉDIO",
    cls: "m",
    title: "Chave de API exposta",
    loc: ".env.local:8",
    desc: "Segredo potencialmente versionável foi detectado.",
    fix: "Adicione o arquivo ao .gitignore, revogue a chave exposta e mova o segredo para um ambiente seguro.",
  },
];

function renderFindings() {
  const wrap = document.getElementById("report-list");
  if (!wrap) return;
  wrap.innerHTML = scanData
    .map(
      (f, i) => `<div class="finding" id="finding-${i}">
   <div class="finding-head" onclick="toggleFinding(${i})"><span class="sev ${f.cls} mono">${f.sev}</span><span class="finding-title">${f.title}</span><span class="finding-loc mono">${f.loc}</span></div>
   <div class="finding-body"><p>${f.desc}</p><div class="fix"><strong>Correção sugerida:</strong><br>${f.fix}</div></div>
 </div>`,
    )
    .join("");
}
function toggleFinding(i) {
  document.getElementById("finding-" + i)?.classList.toggle("open");
}

function runScan() {
  const wrap = document.getElementById("progress-wrap");
  const bar = document.getElementById("progress-bar");
  const pct = document.getElementById("progress-pct");
  const label = document.getElementById("progress-label");
  const report = document.getElementById("report");
  if (!wrap || !bar || !pct || !label || !report) return;
  wrap.classList.remove("hidden");
  report.classList.add("hidden");
  bar.style.width = "0%";
  const labels = [
    "Conectando ao repositório...",
    "Mapeando arquivos...",
    "Executando regras...",
    "Verificando dependências...",
    "Montando relatório...",
  ];
  let p = 0;
  const timer = setInterval(() => {
    p = Math.min(100, p + Math.random() * 16 + 8);
    bar.style.width = p + "%";
    pct.textContent = Math.round(p) + "%";
    label.textContent = labels[Math.min(labels.length - 1, Math.floor(p / 20))];
    if (p >= 100) {
      clearInterval(timer);
      setTimeout(() => {
        renderFindings();
        report.classList.remove("hidden");
        report.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 250);
    }
  }, 190);
}
window.runScan = runScan;
window.toggleFinding = toggleFinding;

function switchTab(mode) {
  document
    .querySelectorAll("[data-tab]")
    .forEach((t) => t.classList.toggle("active", t.dataset.tab === mode));
  document
    .getElementById("panel-github")
    ?.classList.toggle("hidden", mode !== "github");
  document
    .getElementById("panel-chat")
    ?.classList.toggle("hidden", mode !== "chat");
}
window.switchTab = switchTab;

let chatStep = 0;
function sendChat() {
  const input = document.getElementById("chat-input");
  const box = document.getElementById("chat-box");
  if (!input || !box || !input.value.trim()) return;
  const user = input.value.trim();
  const me = document.createElement("div");
  me.className = "msg me";
  me.textContent = user;
  box.appendChild(me);
  input.value = "";
  chatStep++;
  setTimeout(() => {
    const ai = document.createElement("div");
    ai.className = "msg ai";
    ai.textContent =
      chatStep === 1
        ? "Recebi o trecho. Encontrei padrões que merecem atenção em entrada de dados, sanitização e autenticação. Digite “gerar relatório” para continuar."
        : "Relatório demo gerado. Use a análise do repositório para simular a leitura completa do projeto.";
    box.appendChild(ai);
    box.scrollTop = box.scrollHeight;
  }, 420);
}
window.sendChat = sendChat;

function animateCounters() {
  document.querySelectorAll("[data-counter]").forEach((el) => {
    const target = Number(el.dataset.counter);
    const suffix = el.dataset.suffix || "";
    let start = 0;
    const dur = 850;
    const t0 = performance.now();
    function tick(t) {
      const k = Math.min(1, (t - t0) / dur);
      start = Math.floor(target * (1 - Math.pow(1 - k, 3)));
      el.textContent = start.toLocaleString("pt-BR") + suffix;
      if (k < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  });
}
if (document.querySelector("[data-counter]")) animateCounters();

function filterStats(kind) {
  document
    .querySelectorAll(".filter-btn")
    .forEach((b) => b.classList.toggle("active", b.dataset.filter === kind));
  const values = {
    all: [68, 42, 54, 61, 76, 55, 88, 94],
    python: [44, 28, 39, 47, 52, 34, 63, 72],
    web: [24, 14, 15, 14, 24, 21, 25, 22],
  };
  const data = values[kind] || values.all;
  document
    .querySelectorAll(".bar")
    .forEach((b, i) => (b.style.height = data[i] + "%"));
}
window.filterStats = filterStats;

function toggleAuth(mode) {
  const signup = mode === "signup";
  document.getElementById("name-wrap")?.classList.toggle("hidden", !signup);
  document.getElementById("auth-title").textContent = signup
    ? "Crie sua conta"
    : "Bem-vindo de volta";
  document.getElementById("auth-copy").textContent = signup
    ? "Crie um acesso demo para acompanhar análises e repositórios."
    : "Entre para abrir o painel de análises e o histórico do projeto.";
  document.getElementById("auth-submit").textContent = signup
    ? "Criar conta"
    : "Entrar";
  document.getElementById("auth-mode").value = mode;
  document.getElementById("switch-note").innerHTML = signup
    ? 'Já tem uma conta? <button type="button" onclick="toggleAuth(\'login\')">Entrar</button>'
    : 'Ainda não tem conta? <button type="button" onclick="toggleAuth(\'signup\')">Criar conta grátis</button>';
}
window.toggleAuth = toggleAuth;
function handleAuth(e) {
  e.preventDefault();
  window.location.href = "dashboard.html";
}
window.handleAuth = handleAuth;
