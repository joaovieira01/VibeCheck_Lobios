export function setSessionCookie(res, sessionId) {
  res.cookie("session", sessionId, { httpOnly: true, sameSite: "lax" });
}
