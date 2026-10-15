import Router from '@koa/router';

const router = new Router();

router.post('/retry', async (ctx) => {
  const attempts = Number(ctx.request.body.attempts);
  let tries = 0;
~>  while (tries < attempts) {
    await ping();
    tries++;
  }
  ctx.body = { tries };
});

export default router;
