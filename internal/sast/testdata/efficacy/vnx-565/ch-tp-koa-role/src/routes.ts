import Router from '@koa/router';

const router = new Router();

router.delete('/users/:id', async (ctx) => {
~>  const role = ctx.cookies.get('role');
  if (role !== 'admin') ctx.throw(403);
  await deleteUser(ctx.params.id);
});

export default router;
