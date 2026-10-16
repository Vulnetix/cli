const Router = require('@koa/router');
const stats = require('../stats');

const router = new Router();

router.get('/stats.jsonp', async (ctx) => {
  const fn = ctx.query.callback;
  const body = JSON.stringify(await stats.summary());
  ctx.type = 'application/javascript';
~>  ctx.body = fn + '(' + body + ')';
});

module.exports = router;
