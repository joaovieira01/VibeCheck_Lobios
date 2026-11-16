import jwt from "jsonwebtoken";

export function issueToken(claims) {
  return jwt.sign(claims, "demo-jwt-secret-only");
}
