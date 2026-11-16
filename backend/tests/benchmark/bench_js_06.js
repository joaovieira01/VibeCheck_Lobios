export function newSessionId() {
  const sessionId = Math.random();
  return sessionId.toString(36);
}
