const Router = require('@koa/router');
const router = new Router();

router.post('/hooks/github', async (ctx) => {
  const event = ctx.get('X-GitHub-Event');
~>  const payload = JSON.parse(
    ctx.request.body.payload
  );
  await queue.push({ event, payload });
  ctx.status = 202;
});

module.exports = router;
