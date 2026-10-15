const Koa = require('koa');
const app = new Koa();

app.use(async (ctx, next) => {
~>  ctx.set('Access-Control-Allow-Origin', '*');
  await next();
});

app.listen(3000);
