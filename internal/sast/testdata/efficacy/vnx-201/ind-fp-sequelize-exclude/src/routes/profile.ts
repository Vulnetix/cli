import { Router } from 'express';
import { User } from '../models';

const router = Router();

router.get('/profile/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id, {
    attributes: { exclude: ['password', 'resetToken'] },
  });
  res.json(user);
});

router.get('/profile/:id/plain', async (req, res) => {
  const record = await User.findByPk(req.params.id);
  const data = record.toJSON();
  delete data.password;
  delete data.resetToken;
  res.json(data);
});

export default router;
