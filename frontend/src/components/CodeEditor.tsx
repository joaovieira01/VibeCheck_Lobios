import { useRef, type UIEvent } from "react";

type TokenKind = "keyword" | "string" | "number" | "comment" | "function" | "property" | "operator";

type CodeToken = {
  text: string;
  kind: TokenKind | null;
};

const COMMON_KEYWORDS = new Set([
  "async", "await", "break", "case", "catch", "class", "const", "continue",
  "default", "do", "else", "export", "extends", "false", "finally", "for",
  "from", "function", "if", "import", "in", "let", "new", "null", "of",
  "return", "static", "switch", "this", "throw", "true", "try", "typeof",
  "undefined", "var", "void", "while", "with", "yield",
]);

const PYTHON_KEYWORDS = new Set([
  "and", "as", "assert", "async", "await", "break", "class", "continue",
  "def", "del", "elif", "else", "except", "False", "finally", "for", "from",
  "global", "if", "import", "in", "is", "lambda", "None", "nonlocal", "not",
  "or", "pass", "raise", "return", "True", "try", "while", "with", "yield",
]);

const SQL_KEYWORDS = new Set([
  "alter", "and", "as", "by", "create", "delete", "drop", "from", "group",
  "having", "insert", "into", "join", "limit", "not", "null", "on", "or",
  "order", "select", "set", "table", "update", "values", "where",
]);

function languageFor(filename: string): string {
  const extension = filename.split(".").pop()?.toLowerCase() ?? "";
  if (["py", "pyi"].includes(extension)) return "python";
  if (["json", "jsonc"].includes(extension)) return "json";
  if (["sql"].includes(extension)) return "sql";
  if (["yml", "yaml"].includes(extension)) return "yaml";
  if (["html", "htm", "xml"].includes(extension)) return "html";
  if (["js", "jsx", "ts", "tsx", "mjs", "cjs"].includes(extension)) return "javascript";
  return "plain";
}

export function tokenizeCode(source: string, filename: string): CodeToken[] {
  const language = languageFor(filename);
  if (language === "plain") return [{ text: source, kind: null }];
  const comments = [
    language === "python" || language === "yaml" ? "#[^\\n]*" : "",
    language === "sql" ? "--[^\\n]*" : "",
    language === "html" ? "<!--[\\s\\S]*?-->" : "",
    language === "javascript" || language === "sql"
      ? "\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/"
      : "",
  ].filter(Boolean);
  const strings = language === "python"
    ? `(?:\"\"\"[\\s\\S]*?\"\"\"|'''[\\s\\S]*?'''|"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*')`
    : `(?:\`(?:\\\\.|[^\`\\\\])*\`|"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*')`;
  const commentPattern = comments.length ? `(?<comment>${comments.join("|")})` : "(?<comment>\\b\\B)";
  const pattern = new RegExp(
    `${commentPattern}|(?<string>${strings})|(?<number>\\b\\d+(?:\\.\\d+)?\\b)|(?<identifier>[A-Za-z_$][\\w$]*)|(?<operator>===|!==|=>|==|!=|<=|>=|\\+\\+|--|&&|\\|\\||\\?\\?|[+*/%=&|!<>?:~-])`,
    "g",
  );
  const keywords = language === "python"
    ? PYTHON_KEYWORDS
    : language === "sql"
      ? SQL_KEYWORDS
      : COMMON_KEYWORDS;
  const tokens: CodeToken[] = [];
  let cursor = 0;

  for (const match of source.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (index > cursor) tokens.push({ text: source.slice(cursor, index), kind: null });
    const text = match[0];
    const groups = match.groups ?? {};
    let kind: TokenKind | null = null;
    if (groups.comment !== undefined) {
      kind = "comment";
    } else if (groups.string !== undefined) {
      kind = language === "json" && /^\s*:/.test(source.slice(index + text.length))
        ? "property"
        : "string";
    } else if (groups.number !== undefined) {
      kind = "number";
    } else if (groups.identifier !== undefined) {
      if (keywords.has(text)) {
        kind = "keyword";
      } else if (
        (language === "json" || language === "yaml")
        && /^\s*:/.test(source.slice(index + text.length))
      ) {
        kind = "property";
      } else if (/^\s*\(/.test(source.slice(index + text.length))) {
        kind = "function";
      }
    } else if (groups.operator !== undefined) {
      kind = "operator";
    }
    tokens.push({ text, kind });
    cursor = index + text.length;
  }

  if (cursor < source.length) tokens.push({ text: source.slice(cursor), kind: null });
  return tokens;
}

type CodeEditorProps = {
  filename: string;
  source: string;
  onChange: (source: string) => void;
};

export function CodeEditor({ filename, source, onChange }: CodeEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const highlightRef = useRef<PreElement>(null);
  const lineCount = Math.max(10, source.split(/\r?\n/).length);

  function syncScroll(event: UIEvent<HTMLTextAreaElement>) {
    const { scrollTop, scrollLeft } = event.currentTarget;
    if (gutterRef.current) gutterRef.current.scrollTop = scrollTop;
    if (highlightRef.current) {
      highlightRef.current.style.transform = `translate(${-scrollLeft}px, ${-scrollTop}px)`;
    }
  }

  const tokens = tokenizeCode(source, filename);

  return (
    <div className="editor-body">
      <div className="line-gutter" aria-hidden="true" ref={gutterRef}>
        {Array.from({ length: lineCount }, (_, index) => (
          <span key={index}>{index + 1}</span>
        ))}
      </div>
      <div className="editor-code">
        <pre className="editor-highlight" aria-hidden="true" ref={highlightRef}>
          <code>{tokens.map((token, index) => (
            <span className={token.kind ? `syntax-${token.kind}` : undefined} key={index}>
              {token.text}
            </span>
          ))}</code>
        </pre>
        <textarea
          ref={textareaRef}
          value={source}
          onChange={(event) => onChange(event.target.value)}
          onScroll={syncScroll}
          placeholder={"# Cole seu código aqui\n\n# Você também pode carregar um dos exemplos vulneráveis"}
          aria-label="Código fonte para análise"
          spellCheck={false}
          maxLength={1_000_000}
        />
      </div>
    </div>
  );
}

type PreElement = HTMLPreElement;
