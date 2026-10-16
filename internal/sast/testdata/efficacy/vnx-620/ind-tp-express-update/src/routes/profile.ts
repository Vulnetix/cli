import { Router } from 'express'
import bcrypt from 'bcrypt'
import { User } from '../models'

const router = Router()

router.post('/profile/password', async (req, res) => {
  const { newPassword } = req.body
  const user = await User.findByPk(req.session.userId)
  const hashed = await bcrypt.hash(newPassword, 12)
~>  await user.update({ password: hashed })
  res.json({ ok: true })
})

export default router
