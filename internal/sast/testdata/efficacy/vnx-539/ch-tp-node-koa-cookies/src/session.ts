import Router from '@koa/router';

const router = new Router();

router.post('/session', async (ctx) => {
  const jwt = await signUser(ctx.request.body);
~>  ctx.cookies.set('auth_token', jwt, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 180 });
  ctx.status = 204;
});

export default router;
