import { Request, Response, NextFunction } from 'express';
import { UserModel } from '../models/user';

export function recordLogin() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await UserModel.findByPk(req.body.id);
      const saved = await user?.update({ lastLoginAt: new Date() });
~>      res.json(saved);
    } catch (err) {
      next(err);
    }
  };
}

export async function rename(req: Request, res: Response) {
  const user = await UserModel.findByPk(req.body.id, { attributes: ['id', 'name'] });
  const saved = await user?.update({ name: req.body.name });
  res.json(saved);
}
