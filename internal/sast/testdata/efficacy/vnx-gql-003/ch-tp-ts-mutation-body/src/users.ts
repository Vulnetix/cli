import type { Request, Response } from 'express';
import { request as gqlRequest } from 'graphql-request';

const ENDPOINT = 'https://api.internal/graphql';

export async function rename(req: Request, res: Response) {
  const newName = req.body.name;
  const mutation = `
    mutation {
~>      renameUser(id: "${req.params.id}", name: "${newName}") {
        id
      }
    }
  `;
  res.json(await gqlRequest(ENDPOINT, mutation));
}
