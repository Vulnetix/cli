import { Request, Response } from 'express'

export function sessionInfo(req: Request, res: Response) {
  const raw = req.cookies.session
  const parts = raw.split('|')
  const userId = parts[0]
~>  const expires = new Date(parts[1])
  res.json({ userId, expires })
}
