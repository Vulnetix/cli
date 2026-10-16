const Router = require('@koa/router');

const router = new Router();

router.get('/status', (ctx) => {
  ctx.type = 'application/json';
~>  ctx.body = JSON.stringify(process.env);
});

module.exports = router;
