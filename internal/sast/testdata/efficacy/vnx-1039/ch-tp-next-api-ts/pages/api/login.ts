import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const verify = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `secret=${process.env.RECAPTCHA_SECRET}&response=${req.body.token}`,
  });
  const outcome: { success: boolean } = await verify.json();
~>  if (outcome.success !== true) {
    return res.status(403).end();
  }
  return res.status(200).json({ ok: true });
}
