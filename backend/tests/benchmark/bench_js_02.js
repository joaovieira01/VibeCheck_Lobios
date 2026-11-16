export async function lookupUser(db, req) {
  return db.query(`SELECT * FROM users WHERE id = ${req.params.id}`, (error, rows) => rows);
}
