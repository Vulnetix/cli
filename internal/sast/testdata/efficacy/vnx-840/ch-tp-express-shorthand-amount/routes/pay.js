const stripe = require('stripe')(process.env.STRIPE_KEY);

module.exports = async function pay(req, res) {
  const amount = Number(req.body.amount);
~>  const charge = await stripe.charges.create({ amount, currency: 'usd', source: req.body.token });
  res.json({ id: charge.id });
};
