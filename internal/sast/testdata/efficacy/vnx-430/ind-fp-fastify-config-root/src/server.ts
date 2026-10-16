import path from 'node:path';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { config } from './config';

const app = Fastify();

await app.register(fastifyStatic, {
  root: path.join(__dirname, 'public'),
  prefix: '/',
});

await app.register(fastifyStatic, {
  root: config.uploadsDir,
  prefix: '/uploads/',
  decorateReply: false,
});
