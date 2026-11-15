import jwt from "jsonwebtoken";

export function verifySession(token, key) {
  return jwt.verify(token, key, { algorithms: ["HS256"] });
}
