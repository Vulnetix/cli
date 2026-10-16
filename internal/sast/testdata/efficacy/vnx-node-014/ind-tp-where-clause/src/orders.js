app.get('/orders/:id', async (req, res) => {
  const id = req.params.id;
~>  const rows = await db.orders.find({ $where: `this.orderId === '${id}'` }).toArray();
  res.json(rows);
});
