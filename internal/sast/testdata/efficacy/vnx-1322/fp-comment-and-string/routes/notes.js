const fs = require('fs')
const router = require('express').Router()

router.get('/notes', async (req, res) => {
  // fs.readFileSync( would block the event loop here, so use the promise API
  const text = await fs.promises.readFile('notes.txt', 'utf8')
  res.set('x-hint', 'never call fs.readFileSync( in a handler')
  res.send(text)
})

module.exports = router
