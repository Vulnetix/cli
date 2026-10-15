router.patch("/items/:id", async (req, res) => {
~>  await Item.updateOne({ _id: req.params.id }, { $set: req.body });
  res.sendStatus(204);
});
