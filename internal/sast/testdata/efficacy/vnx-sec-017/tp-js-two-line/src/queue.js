const amqp = require('amqplib');

~>const BROKER = 'amqp://jobs:jobspass@broker.acme.io';
async function open() {
  return amqp.connect(BROKER);
}

const client = require('redis').createClient({
~>  url: `redis://${process.env.REDIS_USER}:${process.env.REDIS_PASSWORD}@redis.cluster.acme.io:6379`,
});
