import { ApolloServer } from '@apollo/server';
import { armor } from './armor';
export const server = new ApolloServer({ typeDefs, resolvers, ...armor.protect() });
