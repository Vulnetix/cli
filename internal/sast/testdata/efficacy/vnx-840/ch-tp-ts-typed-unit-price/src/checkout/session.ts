import Stripe from 'stripe';
import { Request, Response } from 'express';

const stripe = new Stripe(process.env.STRIPE_KEY as string);

export async function createSession(req: Request, res: Response) {
  const unitPrice: number = req.body.unitPrice;
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: req.body.name },
~>        unit_amount: unitPrice * 100,
      },
      quantity: 1,
    }],
  });
  res.json({ url: session.url });
}
