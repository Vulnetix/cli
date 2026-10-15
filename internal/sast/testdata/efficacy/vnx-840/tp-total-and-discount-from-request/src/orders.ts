export async function placeOrder(req: Request, res: Response) {
  const cart = await carts.load(req.session.cartId);
~>  const total = cart.subtotal - req.body.discount;
~>  const order = await orders.create({ items: cart.items, total });
~>  order.total = req.body.total;
  await order.save();
}
