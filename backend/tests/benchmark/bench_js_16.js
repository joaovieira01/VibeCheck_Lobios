import crypto from "node:crypto";

export function createApiToken() {
  return crypto.randomBytes(32).toString("hex");
}
