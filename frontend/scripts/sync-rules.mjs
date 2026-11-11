import { copyFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const frontendDirectory = path.resolve(scriptDirectory, "..");
const repositoryDirectory = path.resolve(frontendDirectory, "..");
const source = path.join(repositoryDirectory, "backend", "app", "rules.json");
const destinationDirectory = path.join(frontendDirectory, "src", "data");
const destination = path.join(destinationDirectory, "rules.generated.json");

mkdirSync(destinationDirectory, { recursive: true });
copyFileSync(source, destination);
console.log(`Regras copiadas de ${source} para ${destination}`);
