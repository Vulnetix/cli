import type { ApolloServer } from '@apollo/server';
import type { YogaServerInstance } from 'graphql-yoga';

// The factory below wraps new ApolloServer(...) created elsewhere.
export type AnyServer = ApolloServer | YogaServerInstance<object, object>;

export function describe(server: AnyServer): string {
  return 'createYoga() or new ApolloServer() instance';
}
