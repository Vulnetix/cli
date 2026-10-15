const stripe = require('stripe')(process.env.STRIPE_SECRET);

async function show(id) {
  const pi = await stripe.paymentIntents.retrieve(id);
  const list = await stripe.charges.list({ limit: 10 });
  const customer = await stripe.customers.create({ email: 'a@example.com' });
  const product = await stripe.products.create({ name: 'Gold' });
  const cart = await carts.create({ items: [] });
  return { pi, list, customer, product, cart };
}
