import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import { owaspCategories } from "../data/owasp";
import type { Analysis, Finding } from "../types";

type RGB = [number, number, number];

const ink: RGB = [11, 14, 22];
const purple: RGB = [117, 84, 255];
const lime: RGB = [215, 255, 54];
const muted: RGB = [111, 119, 136];
const paper: RGB = [248, 249, 252];
const danger: RGB = [213, 56, 81];
const orange: RGB = [209, 118, 24];

const severityWeight: Record<Finding["severity"], number> = {
  Crítica: 5,
  Alta: 3,
  Média: 1.5,
  Baixa: 0.5,
};

function text(
  pdf: jsPDF,
  value: string,
  x: number,
  y: number,
  options: { size?: number; color?: RGB; bold?: boolean } = {},
) {
  pdf.setFont("helvetica", options.bold ? "bold" : "normal");
  pdf.setFontSize(options.size ?? 9);
  pdf.setTextColor(...(options.color ?? ink));
  pdf.text(value, x, y);
}

function newPage(pdf: jsPDF, page: number) {
  pdf.addPage();
  pdf.setFillColor(...ink);
  pdf.rect(0, 0, 210, 15, "F");
  pdf.setFillColor(...lime);
  pdf.circle(12, 7.5, 2, "F");
  text(pdf, "VIBECHECK  /  RELATÓRIO DE SEGURANÇA", 19, 9, {
    size: 8,
    color: [255, 255, 255],
    bold: true,
  });
  text(pdf, `PÁGINA ${page}`, 185, 9, {
    size: 7,
    color: [182, 187, 198],
  });
}

function addSectionTitle(pdf: jsPDF, title: string, subtitle?: string) {
  const y = (pdf as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable
    ?.finalY;
  let top = y === undefined ? 25 : y + 13;
  if (top > 263) {
    newPage(pdf, pdf.getNumberOfPages() + 1);
    top = 27;
  }
  text(pdf, title, 14, top, { size: 15, bold: true });
  if (subtitle) {
    text(pdf, subtitle, 14, top + 6, { size: 8, color: muted });
  }
  return top + (subtitle ? 12 : 8);
}

function scoreFor(analysis: Analysis): number {
  const weighted = analysis.findings.reduce(
    (total, finding) =>
      total + severityWeight[finding.severity] * finding.locations.length,
    0,
  );
  return Math.max(5, Math.round(100 * Math.pow(0.86, weighted)));
}

function severityColor(severity: Finding["severity"]): RGB {
  if (severity === "Crítica") return danger;
  if (severity === "Alta") return orange;
  return purple;
}

function compareFindings(left: Finding, right: Finding) {
  return (
    severityWeight[right.severity] - severityWeight[left.severity] ||
    left.locations[0] - right.locations[0]
  );
}

export function buildSecurityReport(analysis: Analysis): jsPDF {
  const pdf = new jsPDF({ format: "a4", unit: "mm" });
  const findings = [...analysis.findings].sort(compareFindings);
  const allOccurrences = findings.reduce(
    (total, finding) => total + finding.locations.length,
    0,
  );
  const critical = findings.reduce(
    (total, finding) =>
      total +
      (finding.severity === "Crítica" ? finding.locations.length : 0),
    0,
  );
  const high = findings.reduce(
    (total, finding) =>
      total + (finding.severity === "Alta" ? finding.locations.length : 0),
    0,
  );
  const score = scoreFor(analysis);
  const verdict =
    critical > 0
      ? "NÃO PUBLICAR — corrija os achados críticos antes do deploy."
      : high > 0
        ? "REVISÃO NECESSÁRIA — priorize os achados altos."
        : findings.length > 0
          ? "ATENÇÃO — revise e valide os achados antes do deploy."
          : "SEM ALERTAS — isso não comprova ausência de vulnerabilidades.";

  pdf.setProperties({
    title: `Relatório de segurança - ${analysis.filename}`,
    subject: "Análise estática de segurança VibeCheck",
    author: "VibeCheck",
    creator: "VibeCheck Frontend",
  });

  pdf.setFillColor(...ink);
  pdf.rect(0, 0, 210, 83, "F");
  pdf.setFillColor(...purple);
  pdf.circle(177, 25, 32, "F");
  pdf.setFillColor(54, 42, 116);
  pdf.circle(185, 28, 22, "F");
  pdf.setFillColor(...lime);
  pdf.circle(192, 33, 3, "F");

  text(pdf, "VIBECHECK  /  SECURITY INTELLIGENCE", 16, 19, {
    size: 8,
    color: lime,
    bold: true,
  });
  text(pdf, "Relatório de", 16, 40, {
    size: 24,
    color: [255, 255, 255],
    bold: true,
  });
  text(pdf, "segurança do código", 16, 51, {
    size: 24,
    color: [255, 255, 255],
    bold: true,
  });
  text(pdf, "ANÁLISE ESTÁTICA  ·  OWASP TOP 10:2025", 16, 62, {
    size: 8,
    color: [183, 188, 204],
    bold: true,
  });

  pdf.setFillColor(...paper);
  pdf.roundedRect(14, 72, 182, 31, 3, 3, "F");
  text(pdf, "ARQUIVO ANALISADO", 20, 82, {
    size: 6.5,
    color: muted,
    bold: true,
  });
  text(pdf, analysis.filename, 20, 90, { size: 11, bold: true });
  text(pdf, "LINGUAGEM", 115, 82, {
    size: 6.5,
    color: muted,
    bold: true,
  });
  text(pdf, analysis.language, 115, 90, { size: 10, bold: true });
  text(pdf, "DATA", 161, 82, { size: 6.5, color: muted, bold: true });
  text(
    pdf,
    new Date(analysis.createdAt).toLocaleDateString("pt-BR"),
    161,
    90,
    { size: 9, bold: true },
  );

  const metrics = [
    { title: "SCORE", value: `${score}/100`, accent: purple },
    { title: "OCORRÊNCIAS", value: String(allOccurrences), accent: ink },
    { title: "CRÍTICOS", value: String(critical), accent: danger },
    { title: "ALTOS", value: String(high), accent: orange },
  ];
  metrics.forEach((metric, index) => {
    const x = 14 + index * 46;
    pdf.setFillColor(...paper);
    pdf.roundedRect(x, 112, 42, 25, 2, 2, "F");
    pdf.setFillColor(...metric.accent);
    pdf.rect(x, 112, 1.3, 25, "F");
    text(pdf, metric.title, x + 4, 119, { size: 6, color: muted, bold: true });
    text(pdf, metric.value, x + 4, 130, {
      size: 15,
      color: metric.accent,
      bold: true,
    });
  });
  text(
    pdf,
    `${analysis.linesAnalyzed.toLocaleString("pt-BR")} linhas · ${analysis.rulesRun} verificações · ${analysis.durationMs} ms`,
    14,
    145,
    { size: 8, color: muted },
  );

  pdf.setFillColor(critical > 0 ? 255 : 242, critical > 0 ? 240 : 238, critical > 0 ? 242 : 255);
  pdf.roundedRect(14, 152, 182, 18, 2, 2, "F");
  pdf.setFillColor(...(critical > 0 ? danger : purple));
  pdf.rect(14, 152, 1.5, 18, "F");
  text(pdf, "VEREDITO", 20, 159, {
    size: 6.5,
    color: critical > 0 ? danger : purple,
    bold: true,
  });
  text(pdf, verdict, 20, 165, {
    size: 8.5,
    color: ink,
    bold: true,
  });

  text(pdf, "Ordem sugerida de correção", 14, 183, {
    size: 14,
    bold: true,
  });
  text(
    pdf,
    "Consolidação por categoria · ordenada por severidade e localização",
    14,
    189,
    { size: 7.5, color: muted },
  );
  autoTable(pdf, {
    startY: 193,
    head: [["#", "SEVERIDADE", "ACHADO", "LOCALIZAÇÕES", "OWASP / CWE"]],
    body: findings.map((finding, index) => [
      String(index + 1).padStart(2, "0"),
      finding.severity.toUpperCase(),
      finding.title,
      finding.locations.join(", "),
      `${finding.owaspId}:2025 · ${finding.cwe}`,
    ]),
    theme: "grid",
    margin: { left: 14, right: 14, bottom: 16 },
    styles: {
      font: "helvetica",
      fontSize: 7,
      cellPadding: 2.4,
      textColor: ink,
      lineColor: [226, 229, 236],
      lineWidth: 0.2,
      overflow: "linebreak",
    },
    headStyles: {
      fillColor: ink,
      textColor: [255, 255, 255],
      fontSize: 6,
      fontStyle: "bold",
    },
    alternateRowStyles: { fillColor: [247, 248, 251] },
    columnStyles: {
      0: { cellWidth: 7 },
      1: { cellWidth: 19 },
      2: { cellWidth: 50 },
      3: { cellWidth: 31 },
      4: { cellWidth: 38 },
    },
    didParseCell(data) {
      if (data.section === "body" && data.column.index === 1) {
        const severity = String(data.cell.raw).toLowerCase();
        data.cell.styles.textColor =
          severity === "crítica"
            ? [...danger]
            : severity === "alta"
              ? [...orange]
              : [...purple];
        data.cell.styles.fontStyle = "bold";
      }
    },
  });

  for (const finding of findings) {
    let startY =
      (pdf as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable
        ?.finalY ?? 30;
    if (startY > 242) {
      newPage(pdf, pdf.getNumberOfPages() + 1);
      startY = 27;
    } else {
      startY += 11;
    }

    const color = severityColor(finding.severity);
    pdf.setFillColor(...color);
    pdf.roundedRect(14, startY - 5, 182, 15, 2, 2, "F");
    text(pdf, finding.severity.toUpperCase(), 19, startY + 1, {
      size: 6.5,
      color: [255, 255, 255],
      bold: true,
    });
    text(pdf, finding.title, 48, startY + 1, {
      size: 9,
      color: [255, 255, 255],
      bold: true,
    });
    text(pdf, `${finding.owaspId}:2025  ·  ${finding.cwe}`, 154, startY + 1, {
      size: 6,
      color: [255, 255, 255],
    });

    const details = [
      ["O QUE FOI IDENTIFICADO", finding.description],
      ["LOCALIZAÇÃO", `${analysis.filename} · linhas ${finding.locations.join(", ")}`],
      [
        "EVIDÊNCIA",
        finding.evidence
          .map((evidence, index) => `${finding.locations[index]}  ${evidence}`)
          .join("\n"),
      ],
      ["COMO RESOLVER", finding.recommendation],
      ["IMPLICAÇÕES DE MANTER", finding.impact],
      ["PREVENÇÃO DE RECORRÊNCIA", finding.prevention],
    ];

    autoTable(pdf, {
      startY: startY + 12,
      body: details,
      theme: "plain",
      margin: { left: 17, right: 16, bottom: 16 },
      styles: {
        font: "helvetica",
        fontSize: 8,
        cellPadding: { top: 2.1, right: 2.5, bottom: 2.1, left: 2.5 },
        textColor: ink,
        overflow: "linebreak",
        valign: "top",
      },
      columnStyles: {
        0: { cellWidth: 40, fontStyle: "bold", textColor: muted },
        1: { cellWidth: 115 },
      },
      didParseCell(data) {
        if (data.section === "body" && data.column.index === 1 && data.row.index === 2) {
          data.cell.styles.font = "courier";
          data.cell.styles.fontSize = 7;
          data.cell.styles.fillColor = [245, 246, 250];
        }
      },
    });
  }

  const categoriesStart =
    (pdf as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable
      ?.finalY ?? 30;
  if (categoriesStart > 235) newPage(pdf, pdf.getNumberOfPages() + 1);
  const categoryY =
    categoriesStart > 235 ? 27 : addSectionTitle(pdf, "Cobertura OWASP Top 10:2025");
  const categoryRows = owaspCategories.map((category) => {
    const count = findings
      .filter((finding) => finding.owaspId === category.id)
      .reduce((sum, finding) => sum + finding.locations.length, 0);
    return [
      `${category.id}:2025`,
      category.title,
      String(count),
      count > 0 ? "Padrão sinalizado" : "Revisão contextual",
    ];
  });
  autoTable(pdf, {
    startY: categoryY,
    head: [["CATEGORIA", "ÁREA", "ACHADOS", "LEITURA"]],
    body: categoryRows,
    theme: "grid",
    margin: { left: 14, right: 14, bottom: 17 },
    styles: {
      font: "helvetica",
      fontSize: 7.5,
      cellPadding: 2.2,
      lineColor: [226, 229, 236],
      lineWidth: 0.2,
      textColor: ink,
    },
    headStyles: {
      fillColor: ink,
      textColor: [255, 255, 255],
      fontSize: 6,
    },
    columnStyles: {
      0: { cellWidth: 16, fontStyle: "bold" },
      1: { cellWidth: 67 },
      2: { cellWidth: 18, halign: "center" },
      3: { cellWidth: 62 },
    },
  });

  const sourceY =
    (pdf as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable
      ?.finalY ?? 30;
  const noteY = sourceY > 252 ? 0 : sourceY + 8;
  if (noteY === 0) newPage(pdf, pdf.getNumberOfPages() + 1);
  const finalY = noteY || 28;
  text(
    pdf,
    "A taxonomia segue o OWASP Top 10:2025. “Revisão contextual” não significa que a categoria esteja segura ou totalmente verificada.",
    14,
    finalY,
    { size: 7, color: muted },
  );
  text(pdf, "FONTES E PRÓXIMOS PASSOS", 14, finalY + 8, {
    size: 6.5,
    color: purple,
    bold: true,
  });
  text(pdf, "OWASP Top 10:2025 · top10.owasp.org/2025/", 14, finalY + 13, {
    size: 7,
    color: ink,
  });
  text(pdf, "Confirme cada achado, aplique a correção e execute uma nova análise.", 14, finalY + 18, {
    size: 7,
    color: ink,
  });

  const pageCount = pdf.getNumberOfPages();
  for (let page = 1; page <= pageCount; page += 1) {
    pdf.setPage(page);
    pdf.setDrawColor(226, 229, 236);
    pdf.line(14, 284, 196, 284);
    text(pdf, "VibeCheck · análise heurística · revisão humana recomendada", 14, 289, {
      size: 6,
      color: muted,
    });
    text(pdf, `${page} / ${pageCount}`, 185, 289, {
      size: 6,
      color: muted,
    });
  }

  return pdf;
}

export function downloadSecurityReport(analysis: Analysis): void {
  const safeName =
    analysis.filename
      .replace(/\.[^.]+$/, "")
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-zA-Z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "") || `analise-${analysis.id}`;
  buildSecurityReport(analysis).save(`vibecheck-relatorio-${safeName}.pdf`);
}
