import { Request, Response } from 'express'

export function login (req: Request, res: Response) {
  const token = sign(req.body.user)
~>  res.cookie('token', token)
~>  res.cookie("session", sessionId, { httpOnly: true, maxAge: 3600000 });
~>  res.cookie('jwt', jwt.sign(payload, key), {
    httpOnly: true,
    sameSite: 'strict'
  })
  res.send('ok')
}
