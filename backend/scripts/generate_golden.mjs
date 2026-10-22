// Gera tests/golden/expected.json rodando o scanner TypeScript ORIGINAL do frontend.
// Uso (Node 22.6+):
//   node --experimental-strip-types scripts/generate_golden.mjs ../VibeCheck_Lobios-frontend
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const frontend = path.resolve(process.argv[2] ?? "../VibeCheck_Lobios-frontend");
const { scanSource } = await import(
  pathToFileURL(path.join(frontend, "src/services/scanner.ts")).href
);
const corpus = JSON.parse(fs.readFileSync("tests/golden/corpus.json", "utf8"));
const expected = Object.fromEntries(
  corpus.map((c) => [c.name, scanSource(c.source, c.filename)]),
);
fs.writeFileSync("tests/golden/expected.json", JSON.stringify(expected, null, 1));
console.log(`${corpus.length} casos gravados`);
