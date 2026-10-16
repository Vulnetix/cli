export async function createIntent(order: Order) {
~>  const intent = await stripe.paymentIntents.create({ amount: order.total, currency: 'eur' });
  return intent.client_secret;
}
