import { Request, Response } from 'express';
import { captchaStore } from '../lib/captchaStore';

export async function submitFeedback(req: Request, res: Response) {
  const captcha = captchaStore.get(req.body.captchaId);
~>  if (captcha && captcha.answer !== String(req.body.captcha)) {
    return res.status(401).json({ error: 'Wrong answer to CAPTCHA' });
  }
  await saveFeedback(req.body.comment);
  res.status(201).end();
}

async function saveFeedback(comment: string) {
  return comment;
}
