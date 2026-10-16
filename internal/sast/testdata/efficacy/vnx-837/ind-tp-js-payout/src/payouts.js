async function sendPayout(vendor) {
  const note = `payout for ${vendor.id}`;
~>  return stripe.payouts.create({
    amount: vendor.owed,
    currency: 'usd',
    description: note,
  });
}
