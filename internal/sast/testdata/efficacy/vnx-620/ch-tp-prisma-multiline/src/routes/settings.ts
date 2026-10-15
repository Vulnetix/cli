import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { prisma } from '../db';

const router = Router();

router.post('/settings/update-password', async (req, res) => {
  const { newPassword } = req.body as { newPassword: string };
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await prisma.user.update({
    where: { id: req.session.userId },
~>    data: { passwordHash: passwordHash },
  });
  res.redirect('/settings');
});

export default router;
