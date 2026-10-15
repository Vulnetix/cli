import { Request, Response } from 'express'

export function readSession (req: Request, res: Response) {
  const raw: string = req.cookies.session
  const parts = raw.split('|')
~>  const expires = new Date(parts[1])
  res.json({ expires })
}
