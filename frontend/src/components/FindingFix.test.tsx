import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { SuggestedFix } from "../types";
import { copySuggestedFix, FindingFix } from "./FindingFix";

const fixes: SuggestedFix[] = [
  {
    before: "  DEBUG = True",
    after: "  DEBUG = False",
    explanation: "Desative o modo de depuração.",
  },
  {
    before: "  verify = False",
    after: "  verify = True",
    explanation: "Mantenha a validação TLS habilitada.",
  },
];

describe("FindingFix", () => {
  it("mostra o diff e o botão de cópia em português", () => {
    const markup = renderToStaticMarkup(
      createElement(FindingFix, { fixes, locations: [4, 8] }),
    );

    expect(markup).toContain("Copiar correção");
    expect(markup).toContain("LINHA 4");
    expect(markup).toContain("ANTES");
    expect(markup).toContain("DEBUG = True");
    expect(markup).toContain("DEBUG = False");
    expect(markup).toContain("Mantenha a validação TLS habilitada.");
  });

  it("copia apenas a correção da ocorrência selecionada", async () => {
    let copied = "";
    await copySuggestedFix(fixes[0], {
      writeText: async (value) => {
        copied = value;
      },
    });

    expect(copied).toBe("  DEBUG = False");
  });

  it("informa erro quando a área de transferência não existe", async () => {
    await expect(copySuggestedFix(fixes[0], undefined)).rejects.toThrow(
      "A área de transferência não está disponível",
    );
  });
});
