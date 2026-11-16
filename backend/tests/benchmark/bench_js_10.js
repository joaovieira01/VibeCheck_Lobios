import crypto from "node:crypto";

export function digestPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}
