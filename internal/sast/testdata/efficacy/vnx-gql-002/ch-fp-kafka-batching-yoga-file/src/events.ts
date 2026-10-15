import { createYoga } from 'graphql-yoga';
import { Kafka } from 'kafkajs';
import { schema } from './schema';

const kafka = new Kafka({ brokers: ['kafka:9092'] });
const producer = kafka.producer({ allowAutoTopicCreation: false });

export const sendEvent = (msg: string) =>
  producer.send({ topic: 'events', messages: [{ value: msg }], acks: -1 });

export const yoga = createYoga({ schema, batching: { limit: 5 } });

const logger = createLogger({ transport: { batching: true, interval: 1000 } });
