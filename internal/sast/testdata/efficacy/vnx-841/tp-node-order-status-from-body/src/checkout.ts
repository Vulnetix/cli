export async function complete(req: Request, res: Response) {
  const checkout = await checkouts.load(req.session.checkoutId);
~>  if (req.query.paid === 'true') {
    checkout.status = 'complete';
    await fulfil(checkout);
  }
  res.redirect('/thanks');
}
