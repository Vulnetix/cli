import { Router } from 'express';
import { User } from '../models/User';

export const users = Router();

users.get('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'not found' });
  }
~>  res.json(user);
});

users.get('/users', async (_req, res) => {
  const all = await User.findAll();
~>  res.status(200).send(all);
});

users.post('/users/me/ip', async (req, res) => {
  const user = await UserModel.findByPk(req.session.uid)
  const updated = await user?.update({ lastLoginIp: req.ip })
~>  res.json(updated)
})
