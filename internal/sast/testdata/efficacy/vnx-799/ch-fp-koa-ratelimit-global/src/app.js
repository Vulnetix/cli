const Koa = require('koa');
const Router = require('@koa/router');
const ratelimit = require('koa-ratelimit');
const Redis = require('ioredis');

const app = new Koa();
const router = new Router();

app.use(
  ratelimit({
    driver: 'redis',
    db: new Redis(),
    duration: 60000,
    max: 10,
  })
);

router.post('/login', async (ctx) => {
  ctx.body = { ok: true };
});

app.use(router.routes());
app.listen(3000);
