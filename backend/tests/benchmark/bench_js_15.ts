export async function addItem(pool, itemId) {
  return pool.query(
    "INSERT INTO items (id) VALUES ($1)",
    [itemId],
  );
}
