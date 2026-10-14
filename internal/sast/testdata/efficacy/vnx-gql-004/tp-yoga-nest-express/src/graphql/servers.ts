import { createYoga } from 'graphql-yoga';
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { graphqlHTTP } from 'express-graphql';
import { schema } from './schema';

~>export const yoga = createYoga({ schema, maskedErrors: true });

@Module({
  imports: [
~>    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
    }),
  ],
})
export class AppModule {}

~>export const legacy = graphqlHTTP({ schema, graphiql: false });
