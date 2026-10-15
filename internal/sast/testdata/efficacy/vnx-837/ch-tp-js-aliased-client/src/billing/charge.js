const Stripe = require('stripe');

const sc = new Stripe(process.env.STRIPE_SECRET);

async function chargeOrder(order) {
~>  const intent = await sc.paymentIntents.create({
    amount: order.totalCents,
    currency: 'usd',
    customer: order.customerId,
    confirm: true,
  });
  return intent.id;
}

module.exports = { chargeOrder };
