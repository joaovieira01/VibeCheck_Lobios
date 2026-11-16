import { Check, Copy } from "lucide-react";
import { useState } from "react";
import type { SuggestedFix } from "../types";

export async function copySuggestedFix(
  fix: SuggestedFix,
  clipboard: Pick<Clipboard, "writeText"> | undefined,
): Promise<void> {
  if (!clipboard) {
    throw new Error("A área de transferência não está disponível neste navegador.");
  }
  await clipboard.writeText(fix.after);
}

export function FindingFix({
  fixes,
  locations,
}: {
  fixes: SuggestedFix[];
  locations: number[];
}) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copyError, setCopyError] = useState<{ index: number; message: string } | null>(null);

  async function copyFix(fix: SuggestedFix, index: number) {
    setCopyError(null);
    try {
      await copySuggestedFix(fix, navigator.clipboard);
      setCopiedIndex(index);
    } catch (error) {
      setCopiedIndex(null);
      setCopyError({
        index,
        message:
          error instanceof Error
            ? error.message
            : "Não foi possível copiar. Selecione e copie o código manualmente.",
      });
    }
  }

  return (
    <section className="finding-fix" aria-label="Correção sugerida">
      <div className="finding-fix-heading">
        <div>
          <span className="detail-label">CORREÇÃO SUGERIDA</span>
          <p>Revise cada alteração e adapte-a ao contexto antes de aplicar.</p>
        </div>
      </div>
      {fixes.map((fix, index) => (
        <div className="finding-fix-item" key={`${locations[index]}-${index}`}>
          <div className="finding-fix-item-heading">
            <span className="finding-fix-line">LINHA {locations[index]}</span>
            <button
              className="finding-fix-copy"
              type="button"
              onClick={() => void copyFix(fix, index)}
            >
              {copiedIndex === index ? <Check size={14} /> : <Copy size={14} />}
              {copiedIndex === index ? "Correção copiada" : "Copiar correção"}
            </button>
          </div>
          <p>{fix.explanation}</p>
          <div className="finding-fix-diff">
            <div className="finding-fix-before">
              <span>ANTES</span>
              <pre><code>{fix.before}</code></pre>
            </div>
            <div className="finding-fix-after">
              <span>DEPOIS</span>
              <pre><code>{fix.after}</code></pre>
            </div>
          </div>
          {copyError?.index === index && (
            <p className="finding-fix-error" role="alert">{copyError.message}</p>
          )}
        </div>
      ))}
      {copiedIndex !== null && (
        <span className="sr-only" aria-live="polite">Correção da linha {locations[copiedIndex]} copiada.</span>
      )}
    </section>
  );
}
