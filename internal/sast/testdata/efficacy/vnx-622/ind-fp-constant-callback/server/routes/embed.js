const router = require('express').Router();

const CALLBACK = 'vulnetixWidgetLoaded';

router.get('/embed.js', (req, res) => {
  const config = { lang: req.acceptsLanguages('en', 'de') || 'en' };
  res.type('application/javascript');
  res.send(CALLBACK + '(' + JSON.stringify(config) + ');');
});

module.exports = router;
