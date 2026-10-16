async function withdraw(req, res) {
  const amount = Number(req.body.amount);
  const account = await Account.findById(req.user.accountId);
  account.balance -= amount;
  await account.save();
  res.json({ balance: account.balance });
}

async function price(req, res) {
  const qty = parseInt(req.query.qty, 10);
  const product = await Product.findById(req.query.id);
~>  res.json({ total: product.price * qty });
}

module.exports = { withdraw, price };
