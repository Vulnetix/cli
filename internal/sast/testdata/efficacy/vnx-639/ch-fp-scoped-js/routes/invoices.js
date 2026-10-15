router.get("/invoices/:id", async (req, res) => {
  const invoice = await Invoice.findOne({ where: { id: req.params.id, userId: req.user.id } });
  res.json(invoice);
});

router.get("/docs/:id", async (req, res) => {
  const doc = await Document.findById(req.params.id);
  if (!doc || doc.ownerId !== req.user.id) {
    return res.sendStatus(403);
  }
  res.json(doc);
});
