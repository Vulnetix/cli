async function a(order) {
  return stripe.paymentIntents.create(
    { amount: order.total, currency: 'eur' },
    { idempotencyKey: `order-${order.id}` },
  );
}

async function b(refund) {
  const opts = { idempotencyKey: `refund-${refund.id}` };
  return stripe.refunds.create({ payment_intent: refund.pi }, opts);
}
