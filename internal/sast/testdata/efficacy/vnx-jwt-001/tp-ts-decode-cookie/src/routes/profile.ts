import { Request, Response } from 'express'
import * as jwt from 'jsonwebtoken'

export function profile (req: Request, res: Response) {
  const session: string = req.cookies.session
~>  const claims = jwt.decode(session) as { email: string }
  res.json({ email: claims.email })
}
