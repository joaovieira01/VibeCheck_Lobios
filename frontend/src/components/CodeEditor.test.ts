import { describe, expect, it } from "vitest";
import { tokenizeCode } from "./CodeEditor";

describe("tokenizeCode", () => {
  it("highlights Python keywords, function names, strings, numbers, and comments", () => {
    const tokens = tokenizeCode(
      'def fetch(url):\n    return "value" + 42 # note',
      "sample.py",
    );

    expect(tokens.filter((token) => token.kind).map(({ text, kind }) => [text, kind]))
      .toEqual([
        ["def", "keyword"],
        ["fetch", "function"],
        [":", "operator"],
        ["return", "keyword"],
        ['"value"', "string"],
        ["+", "operator"],
        ["42", "number"],
        ["# note", "comment"],
      ]);
    expect(tokens.map((token) => token.text).join(""))
      .toBe('def fetch(url):\n    return "value" + 42 # note');
  });

  it("highlights JSON keys separately from values", () => {
    const tokens = tokenizeCode('{"enabled": true}', "config.json");

    expect(tokens.filter((token) => token.kind).map(({ text, kind }) => [text, kind]))
      .toEqual([
        ['"enabled"', "property"],
        [":", "operator"],
        ["true", "keyword"],
      ]);
  });

  it("leaves unsupported languages readable without changing source text", () => {
    const source = "let value = 2;";
    const tokens = tokenizeCode(source, "sample.txt");

    expect(tokens.map((token) => token.text).join("")).toBe(source);
    expect(tokens.filter((token) => token.kind)).toHaveLength(0);
  });
});
