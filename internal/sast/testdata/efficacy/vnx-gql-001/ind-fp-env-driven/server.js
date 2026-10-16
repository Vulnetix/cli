const isDev = process.env.NODE_ENV !== 'production';
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: isDev,
});
app.use('/graphql', graphqlHTTP({
  schema,
  graphiql: process.env.NODE_ENV === 'development',
}));
const other = new ApolloServer({
  typeDefs,
  ...(isDev ? { introspection: true } : {}),
});
