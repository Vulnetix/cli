const Router = require('@koa/router');
const router = new Router();

router.get('/posts', async (ctx) => {
  const page = parseInt(ctx.query.page) || 1;
  const archived = ctx.query.archived;
~>  const showArchived = Boolean(archived);
  ctx.body = await Post.list({ page, showArchived });
});

module.exports = router;
