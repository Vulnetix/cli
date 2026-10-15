import Stripe from 'stripe';

const stripeClient = new Stripe(process.env.STRIPE_KEY!);

export async function refundOrder(chargeId: string): Promise<void> {
~>  await stripeClient.refunds.create({
    charge: chargeId,
  });
}

export async function paySeller(dest: string, amount: number) {
~>  return this.stripe.transfers.create({ amount, currency: 'usd', destination: dest });
}
