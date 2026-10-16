const { Router } = require('express');

const router = Router();

router.post('/link-preview', async (req, res) => {
  const pageUrl = req.body.url;
~>  const response = await fetch(pageUrl, { headers: { 'User-Agent': 'preview-bot/1.0' } });
  const html = await response.text();
  res.status(response.status).send(html);
});

module.exports = router;
