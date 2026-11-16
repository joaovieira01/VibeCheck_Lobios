import express from "express";
const router = express.Router();

router.delete("/invoices/:invoiceId", async (req, res) => {
  await Invoice.deleteOne({ id: req.params.invoiceId });
  res.sendStatus(204);
});

export default router;
