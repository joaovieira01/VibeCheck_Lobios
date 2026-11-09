import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { describe, it } from "vitest";
import type { Finding } from "../types";
import { scanSource } from "./scanner";

const backendPath = resolve(process.cwd(), "..", "backend");
const samplePath = resolve(backendPath, "tests", "samples");
const findingFields: (keyof Finding)[] = [
  "id", "title", "severity", "cwe", "owaspId", "owaspName", "description",
  "recommendation", "impact", "prevention", "locations", "evidence",
];
const pythonScan = [
  "import json, pathlib, sys",
  "sys.path.insert(0, sys.argv[1])",
  "from app.scanner import scan_source",
  "p = pathlib.Path(sys.argv[2])",
  "r = scan_source(p.read_text(encoding='utf-8'), p.name)",
  "print(json.dumps({'findings': [f.to_dict() for f in r.findings], 'rulesRun': r.rules_run}, ensure_ascii=False))",
].join("; ");

describe("scanner implementations on the measurement samples", () => {
  it.each(["amostra_vulneravel.py", "amostra_segura.py"])(
    "lists detection and metadata divergences for %s without changing scanner behavior",
    (filename) => {
      const source = readFileSync(resolve(samplePath, filename), "utf-8");
      const typescriptResult = scanSource(source, filename);
      const pythonResult = JSON.parse(
        execFileSync("python", ["-c", pythonScan, backendPath, resolve(samplePath, filename)], {
          encoding: "utf-8",
        }),
      ) as typeof typescriptResult;
      const sameDetection = (left: Finding, right: Finding) =>
        left.id === right.id &&
        isDeepStrictEqual(left.locations, right.locations) &&
        isDeepStrictEqual(left.evidence, right.evidence);
      const pythonOnly = pythonResult.findings.filter(
        (finding) => !typescriptResult.findings.some((other) => sameDetection(other, finding)),
      );
      const typescriptOnly = typescriptResult.findings.filter(
        (finding) => !pythonResult.findings.some((other) => sameDetection(other, finding)),
      );
      const fieldDifferences = pythonResult.findings.flatMap((finding) => {
        const other = typescriptResult.findings.find(
          (candidate) => sameDetection(candidate, finding),
        );
        if (!other) return [];
        const fields = findingFields.filter(
          (key) => !isDeepStrictEqual(finding[key], other[key]),
        );
        return fields.length ? [{ id: finding.id, fields }] : [];
      });

      console.log(
        `${filename}: ${JSON.stringify({
          pythonOnly: pythonOnly.map(({ id, locations }) => ({ id, locations })),
          typescriptOnly: typescriptOnly.map(({ id, locations }) => ({ id, locations })),
          fieldDifferences,
        })}`,
      );
    },
  );
});
