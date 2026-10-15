import Koa from 'koa';
const app = new Koa();
app.use(async (ctx, next) => {
  try {
    await next();
  } catch (error) {
    ctx.status = 500;
~>    ctx.body = `<h1>Error</h1><pre>${error.stack}</pre>`;
  }
});
