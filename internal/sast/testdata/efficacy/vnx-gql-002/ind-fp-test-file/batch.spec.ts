it('handles batches', async () => {
  const server = new ApolloServer({ schema, allowBatchedHttpRequests: true });
});
