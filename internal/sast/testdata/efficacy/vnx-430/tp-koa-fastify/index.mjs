import Koa from 'koa';
import koaStatic from 'koa-static';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';

const app = new Koa();
~>app.use(koaStatic('.'));

const fastify = Fastify();
fastify.register(fastifyStatic, {
~>  root: __dirname,
  prefix: '/',
});
