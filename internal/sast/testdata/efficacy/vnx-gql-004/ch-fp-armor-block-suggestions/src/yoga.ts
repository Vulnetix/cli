import { createYoga } from 'graphql-yoga';
import { blockFieldSuggestionsPlugin } from '@escape.tech/graphql-armor-block-field-suggestions';
import { schema } from './schema';

export const yoga = createYoga({
  schema,
  plugins: [blockFieldSuggestionsPlugin()],
});
