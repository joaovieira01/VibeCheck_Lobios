export function renderCard(req, res) {
  const label = req.body.label;
  return res.send(`<section>${label}</section>`);
}
