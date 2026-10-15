const Koa = require('koa');
const express = require('express');
const cookieSession = require('cookie-session');

const app = new Koa();
~>app.keys = ['im a newer secret', 'i like turtle'];

const web = express();
web.use(cookieSession({
  name: 'session',
~>  keys: ['k3y-one-rotate-me'],
  maxAge: 24 * 60 * 60 * 1000,
}));
~>web.use('/admin', cookieSession({ name: 'admin', keys: ["admin-cookie-key"] }));

module.exports = { app, web };
