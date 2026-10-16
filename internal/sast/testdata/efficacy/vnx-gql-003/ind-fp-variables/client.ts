const QUERY = `query User($id: ID!) { user(id: $id) { name email } }`;
export async function getUser(req: Request) {
  return client.request(QUERY, { id: req.params.id });
}
export const run = (req) => client.query({ query: gql`query U($id: ID!) { user(id: $id) { id } }`, variables: { id: req.params.id } });
