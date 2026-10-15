const router = require("express").Router();

router.get("/invoices/:invoiceId", async (req, res) => {
~>  const invoice = await Invoice.findByPk(req.params.invoiceId);
  res.json(invoice);
});

router.delete("/docs", async (req, res) => {
  const id = req.query.id;
~>  await Document.findByIdAndDelete(id);
  res.sendStatus(204);
});

module.exports = router;
