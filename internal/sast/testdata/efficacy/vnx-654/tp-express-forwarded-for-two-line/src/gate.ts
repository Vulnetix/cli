import { Request, Response, NextFunction } from 'express'

export function internalOnly (req: Request, res: Response, next: NextFunction) {
  const clientIp = req.headers['x-forwarded-for']
~>  if (clientIp === '10.1.2.3') {
    return next()
  }
  res.status(403).send('forbidden')
}
