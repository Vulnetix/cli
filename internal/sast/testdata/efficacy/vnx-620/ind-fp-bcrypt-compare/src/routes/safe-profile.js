const router = require('express').Router()
const bcrypt = require('bcrypt')

router.post('/profile/password', async (req, res) => {
  const { currentPassword, newPassword } = req.body
  const user = await User.findByPk(req.session.userId)
  if (!(await bcrypt.compare(currentPassword, user.password))) {
    return res.status(401).send('Current password is not correct.')
  }
  user.password = await bcrypt.hash(newPassword, 12)
  await user.save()
  res.json({ ok: true })
})
module.exports = router
