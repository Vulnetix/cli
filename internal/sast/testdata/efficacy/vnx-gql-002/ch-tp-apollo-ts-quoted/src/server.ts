import { ApolloServer } from "@apollo/server";
import { startStandaloneServer } from "@apollo/server/standalone";
import { typeDefs } from "./typeDefs";
import { resolvers } from "./resolvers";

const server = new ApolloServer<{ token?: string }>({
  typeDefs,
  resolvers,
~>  "allowBatchedHttpRequests" : true,
});

await startStandaloneServer(server, { listen: { port: 4000 } });
