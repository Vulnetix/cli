import { createServer } from 'node:http';
import { createYoga } from 'graphql-yoga';
import { schema } from './schema';

~>const yoga = createYoga({ schema, graphiql: true, landingPage: false });

createServer(yoga).listen(4000);
