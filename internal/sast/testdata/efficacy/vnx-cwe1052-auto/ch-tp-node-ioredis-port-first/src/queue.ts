import Redis from 'ioredis';
import { Queue } from 'bullmq';

~>export const redis = new Redis(6379, '10.30.1.4');

export const emails = new Queue('emails', {
  connection: {
~>    host: 'queue-redis.prod.acme-corp.net',
    port: 6379,
  },
});
