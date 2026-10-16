import bcrypt from 'bcrypt';
import { Router } from 'express';
import { db } from '../db';

const router = Router();
const DUMMY_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKcEeO5D0bOGvL/2gVQbZ7xsQ8V4Z5r1y3m1K';

router.post('/session', async (req, res) => {
  const account = await db.accounts.findOne({ where: { email: req.body.email } });
  if (!account) {
    await bcrypt.compare(req.body.password, DUMMY_HASH);
    return res.sendStatus(401);
  }
  if (!(await bcrypt.compare(req.body.password, account.hash))) {
    return res.sendStatus(401);
  }
  res.sendStatus(204);
});

export default router;
