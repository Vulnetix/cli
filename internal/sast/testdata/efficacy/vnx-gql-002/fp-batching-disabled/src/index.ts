import { ApolloServer } from '@apollo/server';
import { createYoga } from 'graphql-yoga';
import { typeDefs, resolvers, schema } from './schema';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: false,
});

export const yoga = createYoga({ schema, batching: process.env.ENABLE_BATCHING === '1' && process.env.NODE_ENV !== 'production' });
