const express = require('express')
const router = express.Router()

// db.query('SELECT * FROM users') was moved to the repository
router.get('/help', (req, res) => {
  logger.info('running SELECT on behalf of %s', req.user.id)
  res.send('Use "db.query(\'SELECT ...\')" only in the data layer')
})

module.exports = router
