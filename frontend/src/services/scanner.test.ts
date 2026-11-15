import { describe, expect, it } from "vitest";
import { owaspCategories } from "../data/owasp";
import { scanSource, scannerRuleCount } from "./scanner";

describe("scanSource", () => {
  it("detects the vulnerable Python demonstration patterns and line references", () => {
    const result = scanSource(
      [
        'SECRET_KEY = "fixed-secret"',
        "DEBUG = True",
        "hashlib.md5(password.encode()).hexdigest()",
        'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "result = eval(expression)",
        'subprocess.check_output("ping " + host, shell=True)',
        "pickle.loads(request.data)",
        "yaml.load(request.data)",
        "requests.get(url, verify=False)",
        'open(BASE_DIR + filename, "rb")',
      ].join("\n"),
      "example.py",
    );

    expect(result.findings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining([
        "sql-injection",
        "hardcoded-secret",
        "dynamic-eval",
        "command-injection",
        "pickle",
        "debug-mode",
        "unsafe-yaml",
        "tls-disabled",
        "path-traversal",
        "weak-password-hash",
      ]),
    );
    expect(result.findings).toHaveLength(10);
    expect(result.findings.find((finding) => finding.id === "sql-injection")?.locations).toEqual([4]);
    expect(result.findings.every((finding) => finding.evidence.length > 0)).toBe(true);
    expect(result.findings.every((finding) => finding.owaspId.startsWith("A"))).toBe(true);
  });

  it("detects JavaScript findings and aggregates repeated occurrences", () => {
    const result = scanSource(
      [
        'const password = "demo-password";',
        'const apiKey = "demo-api-key";',
        'const query = "SELECT * FROM users WHERE id = " + req.params.id;',
        "jwt.verify(token, secret);",
        'const project = "SELECT * FROM projects WHERE id = ?" + projectId;',
        "exec(`convert ${req.body.file} output.png`);",
        "const resetToken = Math.random().toString(36);",
        'res.cookie("session", token, { httpOnly: true });',
        "results.innerHTML = new URLSearchParams(location.search).get('q');",
      ].join("\n"),
      "server.js",
    );

    const secrets = result.findings.find((finding) => finding.id === "hardcoded-secret");
    expect(secrets?.locations).toEqual([1, 2]);
    expect(result.findings.some((finding) => finding.id === "jwt-algorithm")).toBe(true);
    expect(result.findings.some((finding) => finding.id === "idor-project")).toBe(true);
    expect(result.findings.some((finding) => finding.id === "xss-innerhtml")).toBe(true);
    expect(result.findings.some((finding) => finding.id === "weak-random-token")).toBe(true);
  });

  it("does not flag the supplied safe controls", () => {
    const result = scanSource(
      [
        'db_secret = os.environ["APP_DB_SECRET"]',
        'db.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "yaml.safe_load(raw)",
        'subprocess.run(["ping", host], capture_output=True, check=True)',
        "jwt.verify(token, secret, { algorithms: ['HS256'] });",
        "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });",
      ].join("\n"),
      "safe.js",
    );

    expect(result.findings).toEqual([]);
  });

  it("detecta credenciais comuns e preserva os controles seguros", () => {
    const source = [
      'const stripeKey = "sk_live_EXEMPLO1234567890";',
      'const supabaseJwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.assinatura";',
      'const supabaseSecret = "sb_secret_EXEMPLO12345678";',
      'const databaseUrl = "postgresql://usuario:senha@db.example.test/app";',
      'JWT_SECRET = "secret123";',
      'jwt.sign(x, "literal");',
      'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
      'const githubToken = "ghp_EXEMPLO1234567890123456";',
      'const googleKey = "AIzaSyEXEMPLO_NAO_REAL_1234567890";',
      'const slackToken = "xoxb-EXEMPLO-NAO-REAL-123456";',
      "const stripeKey = process.env.STRIPE_KEY;",
      'const dbSecret = os.environ["DB_SECRET"]',
      "const resetToken = secrets.token_urlsafe(32);",
    ].join("\n");
    const result = scanSource(source, "credenciais.js");
    const finding = result.findings.find((item) => item.id === "hardcoded-secret");

    expect(finding?.locations).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(result.findings.some((item) => item.id === "weak-random-token")).toBe(false);
  });

  it("detecta SQL em template literal e aceita consulta parametrizada", () => {
    const result = scanSource(
      [
        "const query = `SELECT * FROM users WHERE id = ${req.params.id}`;",
        'db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);',
      ].join("\n"),
      "consulta.js",
    );
    expect(result.findings.find((item) => item.id === "sql-injection")?.locations).toEqual([1]);
  });

  it("detecta SQL interpolado diretamente em chamadas de banco JavaScript", () => {
    const source = [
      "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`, cb);",
      "pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`, cb);",
      "connection.query(`SELECT * FROM users WHERE id = ${req.params.id}`, cb);",
      "client.query(`SELECT * FROM users WHERE id = ${req.params.id}`, cb);",
      "knex.raw(`SELECT * FROM users WHERE id = ${req.params.id}`);",
      "sequelize.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
      "prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    ].join("\n");
    const finding = scanSource(source, "consultas.js").findings.find(
      (item) => item.id === "sql-injection",
    );

    expect(finding?.locations).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it("aceita placeholders SQL com tupla ou array de parametros", () => {
    const result = scanSource(
      [
        'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
        'pool.query("SELECT * FROM users WHERE id = $1", [userId]);',
        'connection.query("SELECT * FROM users WHERE id = %s", (userId,));',
      ].join("\n"),
      "consultas.js",
    );

    expect(result.findings.some((item) => item.id === "sql-injection")).toBe(false);
  });

  it("detecta token previsivel e aceita gerador criptografico", () => {
    const result = scanSource(
      [
        "const authToken = Math.random().toString(36);",
        "const resetToken = secrets.token_urlsafe(32);",
      ].join("\n"),
      "tokens.js",
    );
    expect(result.findings.find((item) => item.id === "weak-random-token")?.locations).toEqual([
      1,
    ]);
  });

  it("detecta Math.random em identificador de sessao e aceita geradores seguros", () => {
    const result = scanSource(
      [
        "const sessionId = Math.random();",
        "const sessionKey = crypto.randomBytes(32).toString('hex');",
        "const sessionId = crypto.randomUUID();",
      ].join("\n"),
      "session.js",
    );

    expect(result.findings.find((item) => item.id === "weak-random-token")?.locations).toEqual([
      1,
    ]);
  });

  it("detecta aleatoriedade fraca em nomes sensiveis Python", () => {
    const source = [
      "token = str(random.random())",
      "secret = str(random.random())",
      "session = str(random.random())",
      "sid = str(random.random())",
      "otp = random.randint(100000, 999999)",
      "code = random.randint(100000, 999999)",
      "reset = str(random.random())",
      'api_key = "".join(random.choice(chars) for _ in range(32))',
      "password = str(random.random())",
      "senha = str(random.random())",
      "csrf = str(random.random())",
      "nonce = str(random.random())",
    ].join("\n");
    const finding = scanSource(source, "tokens.py").findings.find(
      (item) => item.id === "weak-random-token",
    );

    expect(finding?.locations).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  });

  it("nao sinaliza geradores seguros nem aleatoriedade de uso comum", () => {
    const source = [
      "token = secrets.token_urlsafe(32)",
      "otp = secrets.randbelow(1_000_000)",
      "retry_jitter = random.random()",
      "color = random.choice(colors)",
      "random.shuffle(colors)",
    ].join("\n");

    expect(scanSource(source, "tokens.py").findings).toEqual([]);
  });

  it("detecta hash fraco de pw e restringe mass-assignment", () => {
    const result = scanSource(
      [
        'const pwHash = crypto.createHash("md5").update(req.body.pw).digest("hex");',
        "User.create(req.body);",
        "User.update(req.body);",
        "Object.assign(user, req.body);",
        "const user = { ...req.body };",
        "User.update({ pw: req.body.pw });",
        "crypto.createHash('md5').update(req.body.pw);",
      ].join("\n"),
      "usuarios.js",
    );
    expect(result.findings.find((item) => item.id === "weak-password-hash")?.locations).toEqual([
      1, 7,
    ]);
    expect(result.findings.find((item) => item.id === "mass-assignment")?.locations).toEqual([
      2, 3, 4, 5,
    ]);
  });

  it("detecta XSS em res.send sem reportar escape explícito", () => {
    const result = scanSource(
      [
        "res.send(`<p>${req.body.nome}</p>`);",
        "res.send(`<p>${escapeHtml(req.body.nome)}</p>`);",
      ].join("\n"),
      "resposta.js",
    );
    expect(result.findings.find((item) => item.id === "xss-innerhtml")?.locations).toEqual([1]);
  });

  it("nao gera achados para os novos controles seguros", () => {
    const result = scanSource(
      [
        "const apiKey = process.env.API_KEY;",
        'const dbSecret = os.environ["DB_SECRET"]',
        "const token = secrets.token_urlsafe(32);",
        'db.query("SELECT * FROM users WHERE id = $1", [userId]);',
        "User.update({ pw: req.body.pw });",
      ].join("\n"),
      "controles.js",
    );
    expect(result.findings).toEqual([]);
  });

  it("checks unlocked package manifests and maps all OWASP Top 10 categories", () => {
    const result = scanSource(
      JSON.stringify({
        dependencies: { express: "*", react: "^19.0.0" },
      }),
      "package.json",
    );
    const dependencyFinding = result.findings.find((finding) => finding.id === "unlocked-dependency");

    expect(dependencyFinding?.owaspId).toBe("A03");
    expect(dependencyFinding?.evidence).toContain('"express": "*"');
    expect(owaspCategories).toHaveLength(10);
    expect(scannerRuleCount).toBeGreaterThan(15);
  });

  it("checks Python dependency pins in requirements manifests", () => {
    const result = scanSource("fastapi\nuvicorn>=0.30\n# comment", "requirements.txt");
    const finding = result.findings.find((item) => item.id === "unlocked-dependency");
    expect(finding?.locations).toEqual([1]);
  });

  it("ignores comments and Python block strings while preserving line locations", () => {
    const python = [
      "# eval(expression)",
      '"""',
      "return {'error': 'user not found'}",
      '"""',
      "# pickle.loads(payload)",
      "DEBUG = True  # eval(expression)",
    ].join("\n");
    const pythonResult = scanSource(python, "security.py");
    expect(pythonResult.findings.map((item) => item.id)).toEqual(["debug-mode"]);
    expect(pythonResult.findings[0].locations).toEqual([6]);

    const javascript = [
      "// eval(expression)",
      "/* pickle.loads(payload)",
      "user not found */",
      "const value = true; // yaml.load(raw)",
    ].join("\n");
    expect(scanSource(javascript, "security.ts").findings).toEqual([]);
  });

  it("reports missing authentication on the Python handler and accepts auth dependencies", () => {
    const result = scanSource(
      [
        "@router.delete('/items/{item_id}')",
        "def remove_item(item_id):",
        "    db.items.delete_one({'id': item_id})",
        "@router.delete('/private/{item_id}')",
        "def remove_private(item_id: int = Depends(get_current_user)):",
        "    db.items.delete_one({'id': item_id})",
      ].join("\n"),
      "routes.py",
    );
    expect(
      result.findings.find((finding) => finding.id === "missing-authentication")?.locations,
    ).toEqual([2]);
  });

  it("accepts Express authentication middleware and recognizes unprotected handlers", () => {
    const result = scanSource(
      [
        "router.delete('/items/:id', (req, res) => {",
        "  db.items.deleteMany({ id: req.params.id });",
        "});",
        "router.patch('/private/:id', authMiddleware, (req, res) => {",
        "  db.items.updateMany({ id: req.params.id }, req.body);",
        "});",
      ].join("\n"),
      "routes.js",
    );
    expect(
      result.findings.find((finding) => finding.id === "missing-authentication")?.locations,
    ).toEqual([1]);
  });
});
