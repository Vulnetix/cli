const Koa = require('koa')
const Router = require('@koa/router')
const fs = require('fs')

const app = new Koa()
const router = new Router()

router.get('/report', async (ctx) => {
~>  const entries = fs.readdirSync('/var/reports')
  ctx.body = entries
})

router.get('/raw', async ctx => {
~>  ctx.body = fs.readFileSync('/var/reports/latest.csv')
})

app.use(router.routes())
app.listen(3000)
