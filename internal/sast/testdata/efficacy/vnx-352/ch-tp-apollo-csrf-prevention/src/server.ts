import { ApolloServer } from "@apollo/server";
import { expressMiddleware } from "@apollo/server/express4";
import { typeDefs, resolvers } from "./schema";

const server = new ApolloServer({
  typeDefs,
  resolvers,
~>  csrfPrevention: false,
  introspection: process.env.NODE_ENV !== "production",
});

await server.start();
app.use("/graphql", cors(), express.json(), expressMiddleware(server));
