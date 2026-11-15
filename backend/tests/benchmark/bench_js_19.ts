const trustedHosts = new Set(["api.example.test"]);

export async function fetchRemote(url: URL) {
  if (!trustedHosts.has(url.hostname)) throw new Error("Untrusted host");
  return fetch(url);
}
