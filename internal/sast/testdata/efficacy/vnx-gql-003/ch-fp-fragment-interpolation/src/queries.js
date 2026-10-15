const { gql } = require('graphql-tag');
const { client } = require('./client');

const USER_FIELDS = gql`
  fragment UserFields on User { id name email }
`;

const GET_USER = gql`
  query GetUser($id: ID!) {
    user(id: $id) { ...UserFields }
  }
  ${USER_FIELDS}
`;

async function handler(req, res) {
  const id = req.params.id;
  const result = await client.query({ query: GET_USER, variables: { id } });
  res.json(result.data);
}

module.exports = { handler };
