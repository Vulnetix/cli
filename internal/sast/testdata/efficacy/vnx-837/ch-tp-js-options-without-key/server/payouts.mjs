import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_KEY);

export async function payout(account, cents) {
~>  return stripe.payouts.create(
    { amount: cents, currency: 'eur' },
    { stripeAccount: account },
  );
}
