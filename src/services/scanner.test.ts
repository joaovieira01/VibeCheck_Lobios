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
});
