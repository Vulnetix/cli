import { Request, Response } from 'express'

export function deleteUser (req: Request, res: Response) {
  const role = req.cookies.role
  const level: string = req.body.access_level
~>  if (role === 'admin' || level === 'root') {
    return remove(req.params.id).then(() => res.sendStatus(204))
  }
  res.sendStatus(403)
}
