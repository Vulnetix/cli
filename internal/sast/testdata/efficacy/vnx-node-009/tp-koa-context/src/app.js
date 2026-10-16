import Koa from 'koa';
import Router from '@koa/router';
import axios from 'axios';

const app = new Koa();
const router = new Router();

router.get('/unfurl', async (ctx) => {
  const res = await axios.get(ctx.query.link);
  ctx.body = res.data;
});

router.post('/probe', async (ctx) => {
  const addr = ctx.request.body.address;
~>  const r = await fetch(`http://${addr}`);
  ctx.status = r.status;
});

app.use(router.routes());
export default app;
