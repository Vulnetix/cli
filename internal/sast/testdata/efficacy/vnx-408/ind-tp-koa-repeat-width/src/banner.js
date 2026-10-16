const Router = require('@koa/router');

const router = new Router();

router.get('/banner', async (ctx) => {
  const title = String(ctx.query.title || 'hello');
~>  const rule = '='.repeat(ctx.query.width);
  ctx.body = `${rule}\n${title}\n${rule}`;
});

module.exports = router;
