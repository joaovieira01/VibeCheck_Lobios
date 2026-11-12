import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { scanSource } from "./scanner";

const backendPath = resolve(process.cwd(), "..", "backend");
const samplePath = resolve(backendPath, "tests", "samples");
const goldenPath = resolve(backendPath, "tests", "golden");
const pythonScan = [
  "import json, pathlib, sys",
  "sys.path.insert(0, sys.argv[1])",
  "from app.scanner import scan_source",
  "p = pathlib.Path(sys.argv[2])",
  "r = scan_source(p.read_text(encoding='utf-8'), p.name)",
  "print(json.dumps({'findings': [f.to_dict() for f in r.findings], 'rulesRun': r.rules_run}, ensure_ascii=False))",
].join("; ");

function findPython(): string {
  for (const executable of ["python", "python3"]) {
    const result = spawnSync(executable, ["--version"], { encoding: "utf-8" });
    if (result.status === 0) return executable;
  }
  throw new Error("Python interpreter not found; install python or python3.");
}

const pythonExecutable = findPython();

describe("scanner implementations on the measurement samples", () => {
  it.each(["amostra_vulneravel.py", "amostra_segura.py"])(
    "matches detection rules, lines, and evidence for %s",
    (filename) => {
      const source = readFileSync(resolve(samplePath, filename), "utf-8");
      const typescriptResult = scanSource(source, filename);
      const pythonResult = JSON.parse(
        execFileSync(
          pythonExecutable,
          ["-c", pythonScan, backendPath, resolve(samplePath, filename)],
          {
            encoding: "utf-8",
            env: { ...process.env, PYTHONIOENCODING: "utf-8" },
          },
        ),
      ) as typeof typescriptResult;
      expect(pythonResult).toEqual(typescriptResult);
    },
  );

  it("detects every added rule in its positive golden case and not its negative case", () => {
    const corpus = JSON.parse(
      readFileSync(resolve(goldenPath, "corpus.json"), "utf-8"),
    ) as Array<{
      name: string;
      filename: string;
      source: string;
      ruleCheck?: {
        ruleId: string;
        positiveLine?: number;
        positiveLines?: number[];
        negativeLine: number;
      };
    }>;
    const cases = corpus.filter((item) => item.ruleCheck);
    expect(cases.length).toBeGreaterThanOrEqual(21);
    for (const testCase of cases) {
      const { ruleId, positiveLine, positiveLines, negativeLine } = testCase.ruleCheck!;
      const finding = scanSource(testCase.source, testCase.filename).findings.find(
        (item) => item.id === ruleId,
      );
      expect(finding, testCase.name).toBeDefined();
      for (const line of positiveLines ?? [positiveLine!]) {
        expect(finding?.locations ?? [], testCase.name).toContain(line);
      }
      expect(finding?.locations ?? [], testCase.name).not.toContain(negativeLine);
    }
  });

  it("handles a 1,000-character near-match line within the scan budget", () => {
    const line = `re.match(r'^(a+)+$',${"a".repeat(975)})`.slice(0, 1000).padEnd(1000, "x");
    const started = performance.now();
    scanSource(line, "long.py");
    expect(line).toHaveLength(1000);
    expect(performance.now() - started).toBeLessThan(1000);
  });
});
