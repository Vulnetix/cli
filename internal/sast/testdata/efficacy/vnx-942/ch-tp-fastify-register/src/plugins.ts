import Fastify from 'fastify';
import cors from '@fastify/cors';

const app = Fastify();
~>await app.register(cors);
await app.register(cors, { origin: ['https://app.example.com'] });
