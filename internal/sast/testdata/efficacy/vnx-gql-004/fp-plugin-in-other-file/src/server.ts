import { createYoga } from 'graphql-yoga';
import { securityPlugins } from './plugins/security';
import { schema } from './schema';

export const yoga = createYoga({ schema, plugins: securityPlugins });
