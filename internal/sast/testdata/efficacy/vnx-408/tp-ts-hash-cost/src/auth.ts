import bcrypt from 'bcrypt';
import crypto from 'crypto';

export async function register(req: Request, res: Response) {
  const cost = Number(req.body.cost);
~>  const hash = await bcrypt.hash(req.body.password, cost);
~>  const key = crypto.pbkdf2Sync(req.body.password, salt, req.query.iterations, 64, 'sha512');
  res.json({ hash, key });
}
