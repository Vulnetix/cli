import Stripe from 'stripe';

const stripe = new Stripe('@@sample:s[k][_]test[_]placeholder@@');

it('creates an intent', async () => {
  const pi = await stripe.paymentIntents.create({ amount: 100, currency: 'usd' });
  expect(pi.status).toBeDefined();
});
