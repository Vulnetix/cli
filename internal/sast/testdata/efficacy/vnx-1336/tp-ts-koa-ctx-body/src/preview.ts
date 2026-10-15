import Router from '@koa/router'
import Handlebars from 'handlebars'

export const router = new Router()

router.post('/preview', async (ctx) => {
  const { template } = ctx.request.body as { template: string }
~>  ctx.body = Handlebars.compile(template)({})
})
