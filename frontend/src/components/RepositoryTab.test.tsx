import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RepositoryAnalysisService } from "../types";
import { RepositoryTab } from "./RepositoryTab";

const service: RepositoryAnalysisService = {
  async analyzeRepository() {
    throw new Error("Não esperado neste teste.");
  },
  async getRepositoryHistory() {
    return [];
  },
  async getRepositoryAnalysis() {
    throw new Error("Não esperado neste teste.");
  },
};

describe("RepositoryTab", () => {
  it("explica que a API é necessária no modo local", () => {
    const markup = renderToStaticMarkup(
      createElement(RepositoryTab, { apiEnabled: false, service }),
    );

    expect(markup).toContain("A análise de repositório precisa de uma sessão autenticada");
    expect(markup).toContain("disabled=\"\"");
    expect(markup).toContain('accept=".zip,application/zip"');
  });

  it("apresenta o envio e o limite padrão quando a API está disponível", () => {
    const markup = renderToStaticMarkup(
      createElement(RepositoryTab, { apiEnabled: true, service }),
    );

    expect(markup).toContain("Escolher arquivo ZIP");
    expect(markup).toContain("Limite padrão: 25 MB");
    expect(markup).toContain("Analisar repositório");
    expect(markup).not.toContain("A análise de repositório precisa de uma sessão autenticada");
  });
});
