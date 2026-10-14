import { createYoga } from 'graphql-yoga';
import { schema } from './schema.js';

// Batching is allowed, but no more than five operations per request.
export const yoga = createYoga({
  schema,
  batching: { limit: 5 },
});
