const express = require('express')
const passport = require('passport')
const admin = require('./controllers/admin')

const router = express.Router()
router.use(passport.authenticate('jwt', { session: false }))

router.get('/admin/users', admin.listUsers)
router.post('/admin/promote', admin.promote)

module.exports = router
