const stripe = require('stripe')(process.env.STRIPE_SECRET);

async function pay(order) {
~>  const intent = await stripe.paymentIntents.create({ amount: order.total, currency: 'eur', confirm: true, payment_method: order.pm });
  return intent.id;
}
