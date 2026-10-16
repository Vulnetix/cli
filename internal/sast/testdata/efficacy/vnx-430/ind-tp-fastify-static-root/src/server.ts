import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';

const app = Fastify({ logger: true });

await app.register(fastifyStatic, {
~>  root: __dirname,
  prefix: '/assets/',
});

await app.listen({ port: 3000 });
