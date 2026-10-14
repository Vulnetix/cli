import { Router } from 'express';
import { client } from '../graphql';

export const router = Router();

router.get('/users/:id', async (req, res) => {
~>  const query = `query { user(id: "${req.params.id}") { name email } }`;
  const data = await client.request(query);
  res.json(data);
});
