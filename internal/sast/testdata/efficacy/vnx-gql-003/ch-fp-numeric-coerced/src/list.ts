import { request } from 'graphql-request';

export async function list(req, res) {
  const limit = Number.parseInt(req.query.limit as string, 10) || 20;
  const query = `query { items(first: ${limit}) { id } }`;
  res.json(await request(process.env.GQL_URL!, query));
}
