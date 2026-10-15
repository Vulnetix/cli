const Koa = require('koa');
const cookieSession = require('cookie-session');

const app = new Koa();
app.keys = [@@sample:p[r]oc[e]ss[.]en[v][.]K[O]A[_][K]EY[_]1@@, @@sample:p[r]oc[e]ss[.]en[v][.]K[O]A[_][K]EY[_]2@@];

const opts = cookieSession({ name: 'sess', keys: process.env.SESSION_KEYS.split(',') });
const order = { keys: ['id', 'name'] };

module.exports = { app, opts, order };
