import { ApolloServer } from '@apollo/server';
import { ApolloArmor } from '@escape.tech/graphql-armor';
import { typeDefs, resolvers } from './schema';

const armor = new ApolloArmor({ blockFieldSuggestion: { enabled: true } });

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  ...armor.protect(),
});
