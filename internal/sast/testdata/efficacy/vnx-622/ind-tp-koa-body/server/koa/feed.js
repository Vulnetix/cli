const Router = require('koa-router')
const router = new Router()

router.get('/feed', async (ctx) => {
  const callback = ctx.query.callback
  const items = await Feed.latest()
~>  ctx.body = callback + '(' + JSON.stringify(items) + ')'
})
module.exports = router
