import { ApolloServer } from '@apollo/server';
import { graphqlHTTP } from 'express-graphql';
import { typeDefs, resolvers, schema } from './schema';

const isDev = process.env.NODE_ENV !== 'production';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: isDev,
});

export const legacy = graphqlHTTP({
  schema,
  graphiql: process.env.NODE_ENV === 'development',
});

export const hardened = new ApolloServer({ typeDefs, resolvers, introspection: false });
export const devOnly = new ApolloServer({ typeDefs, resolvers, ...(isDev ? { introspection: true } : {}) });
