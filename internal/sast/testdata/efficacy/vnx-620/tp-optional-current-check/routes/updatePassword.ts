import { type Request, type Response } from 'express'
import { UserModel } from '../models/user'
import { hash } from '../lib/crypto'

export function updatePassword () {
  return async ({ query, headers }: Request, res: Response) => {
    const currentPassword = query.current as string
    const newPassword = query.new as string
    const user = await UserModel.findByPk(sessionUser(headers).id)
    if (!user) {
      return res.status(404).end()
    }
    if (currentPassword && hash(currentPassword) !== user.password) {
      return res.status(401).send('Current password is not correct.')
    }
~>    await user.update({ password: newPassword })
    res.json({ ok: true })
  }
}
