const Koa = require('koa');
const serve = require('koa-static');
const router = require('./router');

const app = new Koa();
~>app.use(serve('.'));
app.use(router.routes());
app.listen(4000);
