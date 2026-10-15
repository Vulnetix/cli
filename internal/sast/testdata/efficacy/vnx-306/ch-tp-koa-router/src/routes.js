const Router = require('@koa/router');
const { Users } = require('./db');

const router = new Router();

~>router.delete('/admin/users/:id', async (ctx) => {
  await Users.destroy({ where: { id: ctx.params.id } });
  ctx.status = 204;
});

module.exports = router;
