const Koa = require('koa');
const app = new Koa();

app.use(async (ctx) => {
~>  ctx.set('X-Request-Name', ctx.query.name);
~>  ctx.response.set('X-Ref', ctx.request.headers.referer);
  ctx.body = 'ok';
});
