import { Request, Response } from 'express';

export async function changePassword(req: Request, res: Response) {
~>  const { current, newPassword, confirmPassword } = req.body;
  if (!(await verify(req.user, current))) {
    return res.status(403).end();
  }
  await setPassword(req.user, newPassword);
  res.status(204).end();
}
