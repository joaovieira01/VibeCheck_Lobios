function showUser(req, res, db) {
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`, (error, rows) => {
    res.send(`<p>${req.body.name}</p>`);
  });
}
