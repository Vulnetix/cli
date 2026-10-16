adminRouter.put('/products/:id', async (req, res) => {
  const product = await Product.findById(req.params.id);
  product.price = req.body.price;
  await product.save();
  res.json(product);
});

function report(rows) {
  return summarise({ total: rows.length, label: 'rows' });
}
