import type { SuggestedFix } from "../types";

function isPython(filename: string): boolean {
  return filename.toLowerCase().endsWith(".py");
}

function isJavaScript(filename: string): boolean {
  return /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(filename);
}

function environmentName(name: string): string {
  const variable = name.split(".").pop() ?? name;
  return variable
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
}

function environmentReference(
  filename: string,
  name: string,
  quote = '"',
): string {
  return isPython(filename)
    ? `os.environ[${quote}${name}${quote}]`
    : `process.env.${name}`;
}

function fixSecret(filename: string, line: string): SuggestedFix | undefined {
  const assignment = line.match(
    /^([ \t]*(?:(?:export\s+)?(?:const|let|var)\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*=\s*)('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")(\s*;?\s*(?:#.*|\/\/.*)?)$/,
  );
  if (assignment) {
    const quote = assignment[3][0];
    const name = environmentName(assignment[2]);
    if (!name) return undefined;
    return {
      before: line,
      after: `${assignment[1]}${environmentReference(filename, name, quote)}${assignment[4]}`,
      explanation: `Defina ${name} no ambiente e garanta que os segredos não sejam versionados.${isPython(filename) ? " Importe os se necessário." : ""}`,
    };
  }

  const jwt = line.match(
    /^([ \t]*jwt\.sign\s*\(\s*[^,\r\n]*,\s*)('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")(\s*(?:,\s*[^)]*)?\)\s*;?\s*(?:\/\/.*)?)$/i,
  );
  if (!jwt) return undefined;
  return {
    before: line,
    after: `${jwt[1]}${environmentReference(filename, "JWT_SECRET", jwt[2][0])}${jwt[3]}`,
    explanation: `Defina JWT_SECRET no ambiente e rotacione a chave que estava no código.${isPython(filename) ? " Importe os se necessário." : ""}`,
  };
}

function fixSql(
  filename: string,
  source: string,
  line: string,
): SuggestedFix | undefined {
  if (isPython(filename)) {
    const match = line.match(
      /^([ \t]*(?:[A-Za-z_]\w*\.)+execute\(\s*)f(['"])(.*?)\2(\s*\)\s*;?\s*(?:#.*)?)$/,
    );
    if (!match) return undefined;
    let placeholder: string;
    if (/\b(?:import\s+sqlite3|from\s+sqlite3\s+import)\b/.test(source)) {
      placeholder = "?";
    } else if (/\b(?:import\s+(?:psycopg|pymysql|MySQLdb)|from\s+(?:psycopg|pymysql|MySQLdb)\b)/.test(source)) {
      placeholder = "%s";
    } else {
      return undefined;
    }
    const sql = match[3];
    const values = Array.from(
      sql.matchAll(/\{([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\}/g),
      (item) => item[1],
    );
    if (!values.length || (sql.match(/\{/g) ?? []).length !== values.length || (sql.match(/\}/g) ?? []).length !== values.length) {
      return undefined;
    }
    const safeSql = sql.replace(/\{[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\}/g, placeholder);
    const params = values.length === 1 ? `${values[0]},` : values.join(", ");
    return {
      before: line,
      after: `${match[1]}${match[2]}${safeSql}${match[2]}, (${params})${match[4]}`,
      explanation: "Envie os valores como parâmetros separados do SQL. Confira se o placeholder corresponde ao driver usado.",
    };
  }

  const match = line.match(
    /^([ \t]*((?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*)\s*\(\s*)`([^`]*)`(\s*\)\s*;?\s*(?:\/\/.*)?)$/,
  );
  if (!match) return undefined;
  const callee = match[2];
  let driver: "knex" | "sequelize" | "prisma" | "pg" | "mysql";
  if (callee === "knex.raw") driver = "knex";
  else if (callee === "sequelize.query") driver = "sequelize";
  else if (callee === "prisma.$queryRawUnsafe") driver = "prisma";
  else if (/(?:from\s*|require\s*\(\s*)["']pg["']/.test(source)) driver = "pg";
  else if (/(?:from\s*|require\s*\(\s*)["']mysql2?["']/.test(source)) driver = "mysql";
  else return undefined;

  const sql = match[3];
  const interpolation = /\$\{([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\}/g;
  const values = Array.from(sql.matchAll(interpolation), (item) => item[1]);
  if (!values.length || (sql.match(/\$\{/g) ?? []).length !== values.length || (sql.match(/\}/g) ?? []).length !== values.length) {
    return undefined;
  }
  let position = 0;
  const safeSql = sql.replace(interpolation, () => {
    position += 1;
    return driver === "pg" || driver === "prisma" ? `$${position}` : "?";
  });
  const params = values.join(", ");
  const binding =
    driver === "sequelize"
      ? `{ replacements: [${params}] }`
      : driver === "prisma"
        ? params
        : `[${params}]`;
  return {
    before: line,
    after: `${match[1]}\`${safeSql}\`, ${binding}${match[4]}`,
    explanation: "Envie os valores como parâmetros separados do SQL. Confira se o placeholder corresponde ao driver usado.",
  };
}

function fixWeakHash(filename: string, line: string): SuggestedFix | undefined {
  if (isPython(filename)) {
    const match = line.match(
      /^([ \t]*)([A-Za-z_]\w*)\s*=\s*hashlib\.(?:md5|sha1)\s*\(\s*([A-Za-z_]\w*\.encode\(\))\s*\)\.hexdigest\(\)(\s*(?:#.*)?)$/i,
    );
    if (!match) return undefined;
    const salt = `${match[2]}_salt`;
    return {
      before: line,
      after: `${match[1]}${salt} = __import__("os").urandom(16)\n${match[1]}${match[2]} = ${salt}.hex() + ":" + hashlib.scrypt(${match[3]}, salt=${salt}, n=16384, r=8, p=1).hex()${match[4]}`,
      explanation: "Use scrypt com salt aleatório e armazene o salt junto do hash; recupere-o para verificar a senha.",
    };
  }

  const match = line.match(
    /^([ \t]*(?:(?:export\s+)?(?:const|let|var)\s+)?)([A-Za-z_$][\w$]*)\s*=\s*crypto\.createHash\((['"])(?:md5|sha1)\3\)\.update\(([A-Za-z_$][\w$]*)\)\.digest\(\3hex\3\);?$/i,
  );
  if (!match) return undefined;
  const salt = `${match[2]}Salt`;
  const quote = match[3];
  return {
    before: line,
    after: `${match[1]}${salt} = crypto.randomBytes(16);\n${match[1]}${match[2]} = \`\${${salt}.toString(${quote}hex${quote})}:\${crypto.scryptSync(${match[4]}, ${salt}, 64).toString(${quote}hex${quote})}\`;`,
    explanation: "Use scrypt com salt aleatório e armazene o salt junto do hash; recupere-o para verificar a senha.",
  };
}

function fixLine(
  ruleId: string,
  filename: string,
  source: string,
  line: string,
): SuggestedFix | undefined {
  const python = isPython(filename);
  if (ruleId === "hardcoded-secret") return fixSecret(filename, line);
  if (ruleId === "sql-injection") return fixSql(filename, source, line);
  if (ruleId === "unsafe-yaml") {
    if ((line.match(/yaml\.load/g) ?? []).length !== 1) return undefined;
    return {
      before: line,
      after: line.replace(/\byaml\.load(?=\s*\()/, "yaml.safe_load"),
      explanation: "Use o carregador seguro do PyYAML para não instanciar objetos arbitrários.",
    };
  }
  if (ruleId === "debug-mode") {
    const matches = Array.from(line.matchAll(/\bdebug\s*=\s*True\b/gi));
    if (matches.length !== 1) return undefined;
    return {
      before: line,
      after: line.replace(/\bdebug\s*=\s*True\b/i, (value) =>
        `${value.slice(0, -4)}${python ? "False" : "false"}`,
      ),
      explanation: "Mantenha o modo de depuração desativado fora de testes locais controlados.",
    };
  }
  if (ruleId === "tls-disabled") {
    const matches = Array.from(line.matchAll(/\bverify\s*=\s*False\b/gi));
    if (matches.length !== 1) return undefined;
    return {
      before: line,
      after: line.replace(/\bverify\s*=\s*False\b/i, (value) =>
        `${value.slice(0, -5)}${python ? "True" : "true"}`,
      ),
      explanation: "Mantenha a validação do certificado TLS habilitada.",
    };
  }
  if (ruleId === "weak-random-token") {
    const match = line.match(
      /^([ \t]*(?:(?:const|let|var)\s+)?[A-Za-z_$][\w$]*\s*=\s*)(.*?)(\s*;?\s*(?:#.*|\/\/.*)?)$/,
    );
    if (!match) return undefined;
    const replacement = python
      ? "secrets.token_urlsafe(32)"
      : 'crypto.randomBytes(32).toString("hex")';
    return {
      before: line,
      after: `${match[1]}${replacement}${match[3]}`,
      explanation: "Use um gerador criptograficamente seguro; importe secrets em Python ou crypto de node:crypto em Node.js.",
    };
  }
  if (ruleId === "wildcard-cors") {
    const matches = Array.from(
      line.matchAll(/\b(?:origin|origins)\s*[:=]\s*(['"])\*\1/gi),
    );
    if (matches.length !== 1) return undefined;
    const quote = matches[0][1];
    const replacement = environmentReference(
      filename,
      "CORS_ALLOWED_ORIGIN",
      quote,
    );
    return {
      before: line,
      after: line.replace(/\b(?:origin|origins)\s*[:=]\s*(['"])\*\1/i, (value) =>
        value.replace(/(['"])\*\1/, replacement),
      ),
      explanation: `Configure CORS_ALLOWED_ORIGIN com uma origem confiável e não use o curinga em produção.${python ? " Importe os se necessário." : ""}`,
    };
  }
  if (ruleId === "server-all-interfaces") {
    const matches = Array.from(line.matchAll(/(['"])0\.0\.0\.0\1/g));
    if (matches.length !== 1) return undefined;
    return {
      before: line,
      after: line.replace(/(['"])0\.0\.0\.0\1/, (_value, quote: string) => `${quote}127.0.0.1${quote}`),
      explanation: "Limite o servidor de desenvolvimento à interface local.",
    };
  }
  if (ruleId === "weak-password-hash") return fixWeakHash(filename, line);
  if (ruleId === "dynamic-eval") {
    if ((line.match(/\beval(?=\s*\()/g) ?? []).length !== 1) return undefined;
    return {
      before: line,
      after: line.replace(/\beval(?=\s*\()/, python ? "ast.literal_eval" : "JSON.parse"),
      explanation: `Faça parsing apenas de dados.${python ? " Importe ast em Python;" : ""} literal_eval aceita literais Python; JSON.parse aceita somente JSON válido.`,
    };
  }
  return undefined;
}

export function suggestedFixesFor(
  ruleId: string,
  filename: string,
  source: string,
  locations: number[],
): SuggestedFix[] | undefined {
  if (!isPython(filename) && !isJavaScript(filename)) return undefined;
  const lines = source.split(/\r?\n/);
  const fixes: SuggestedFix[] = [];
  for (const location of locations) {
    if (location < 1 || location > lines.length) return undefined;
    const fix = fixLine(ruleId, filename, source, lines[location - 1]);
    if (!fix) return undefined;
    fixes.push(fix);
  }
  return fixes.length > 0 ? fixes : undefined;
}
