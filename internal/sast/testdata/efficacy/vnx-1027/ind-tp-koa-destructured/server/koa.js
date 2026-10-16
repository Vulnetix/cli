const Router = require('koa-router');
const router = new Router();

router.get('/load', async (ctx) => {
  const { module: name } = ctx.query;
~>  const m = require.resolve('./mods/' + name);
  ctx.body = m;
});
