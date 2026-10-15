import type { CodegenConfig } from '@graphql-codegen/cli';

// Generates typed hooks for the ApolloClient; not a server.
const config: CodegenConfig = {
  schema: 'http://localhost:4000/graphql',
  documents: ['src/**/*.tsx'],
  generates: {
    './src/gql/': { preset: 'client' },
    './graphql.schema.json': { plugins: ['introspection'], config: { introspection: true } },
  },
};

export default config;
