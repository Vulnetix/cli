import { Router } from 'express';
import bcrypt from 'bcrypt';
import { requireRole } from '../auth';
import { Users } from '../models';

export const adminRouter = Router();

adminRouter.post('/admin/users/:id/password', requireRole('admin'), async (req, res) => {
  const user = await Users.findByPk(req.params.id);
  if (!user) return res.sendStatus(404);
  await user.update({ password: await bcrypt.hash(req.body.password, 12) });
  res.sendStatus(204);
});
