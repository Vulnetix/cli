exports.topUp = async (req, res) => {
  const { amount, currency } = req.body;
  const wallet = await Wallet.findOne({ userId: req.user.id });
~>  wallet.balance = wallet.balance + amount;
  await wallet.save();
  const charge = await stripe.charges.create({
~>    amount: amount,
    currency,
    customer: req.user.stripeId,
  });
  res.json({ balance: wallet.balance, charge: charge.id });
};
