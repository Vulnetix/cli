async function withdraw(req, res) {
  const amount = Number(req.body.amount);
  if (!Number.isInteger(amount) || amount < 1) {
    return res.status(400).end();
  }
  const account = await Account.findById(req.user.accountId);
  account.balance -= amount;
  await account.save();
  res.end();
}

module.exports = { withdraw };
