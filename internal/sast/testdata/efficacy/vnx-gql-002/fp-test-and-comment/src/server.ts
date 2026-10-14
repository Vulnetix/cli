import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

// allowBatchedHttpRequests: true would let one request carry many operations.
export const server = new ApolloServer({ typeDefs, resolvers });
export const note = "allowBatchedHttpRequests: true is off by default";
