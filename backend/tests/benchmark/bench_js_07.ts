export async function loadPreview(req: Request) {
  const target = new URL(req.url).searchParams.get("target");
  return fetch(target!);
}
