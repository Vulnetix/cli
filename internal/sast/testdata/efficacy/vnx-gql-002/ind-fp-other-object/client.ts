import { DataLoader } from 'dataloader';
const link = createHttpLink({
  uri: '/graphql',
  transport: { batching: true },
});
const config = { cache: { batching: true } };
