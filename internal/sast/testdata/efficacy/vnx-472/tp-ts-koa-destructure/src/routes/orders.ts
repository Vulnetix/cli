import Router from '@koa/router';

const router = new Router();

router.post('/orders', async (ctx) => {
~>  const { productId, unitPrice, quantity } = ctx.request.body as OrderInput;
~>  const shipping = Number(ctx.request.body.shippingCost);
  ctx.body = await createOrder(productId, unitPrice * quantity + shipping);
});

export default router;
