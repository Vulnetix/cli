import { Request, Response } from 'express';

export async function addRole(req: Request, res: Response) {
  const user = await repo.findOneByOrFail({ id: req.params.id });
  const wanted = req.body.role;
~>  user.roles.push(wanted);
  await repo.save(user);
  res.json(user);
}
