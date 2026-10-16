export function price(req: Request, cart: Cart) {
~>  const total = cart.subtotal - req.body.discount;
  return total;
}
