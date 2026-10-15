import { Request, Response, NextFunction } from 'express'

export function staffOnly (req: Request, res: Response, next: NextFunction) {
  const flag = req.cookies.staff_mode
~>  if (flag === 'enabled') {
    return next()
  }
  res.status(403).end()
}
