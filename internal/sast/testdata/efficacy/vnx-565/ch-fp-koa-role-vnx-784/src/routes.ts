import Router from '@koa/router';

const router = new Router();

router.delete('/users/:id', async (ctx) => {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  const role = ctx.cookies.get('role');
  if (role !== 'admin') ctx.throw(403);
  await deleteUser(ctx.params.id);
});

export default router;
