const express = require('express');
const router = express.Router();

router.get('/preview', async (req, res) => {
  try {
~>    const page = await fetch(req.query.url, { redirect: 'follow' });
    const html = await page.text();
    const title = (html.match(/<title>(.*?)<\/title>/i) || [])[1];
    res.json({ title: title || null, length: html.length });
  } catch (err) {
    res.status(502).json({ error: 'upstream failed' });
  }
});

module.exports = router;
