const stripe = require('stripe')(process.env.STRIPE_KEY);

async function capture(order) {
  const requestOptions = { idempotencyKey: `order-${order.id}` };
  return stripe.paymentIntents.create(
    { amount: order.cents, currency: 'usd', customer: order.customer },
    requestOptions,
  );
}

module.exports = { capture };
