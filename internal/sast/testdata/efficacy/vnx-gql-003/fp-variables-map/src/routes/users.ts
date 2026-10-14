import { Router } from 'express';
import { gql } from 'graphql-tag';
import { client, apollo } from '../graphql';

const GET_USER = gql`
  query GetUser($id: ID!) {
    user(id: $id) { name email }
  }
`;

export const router = Router();

router.get('/users/:id', async (req, res) => {
  const { data } = await apollo.query({ query: GET_USER, variables: { id: req.params.id } });
  const raw = await client.request(`query ($id: ID!) { user(id: $id) { name } }`, { id: req.params.id });
  res.json({ data, raw });
});
