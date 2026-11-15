export async function register(req, res) {
  const profile = await Profile.create(req.body);
  return res.json(profile);
}
