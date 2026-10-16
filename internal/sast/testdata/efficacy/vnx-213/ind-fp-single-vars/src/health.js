const router = require('express').Router();

router.get('/healthz', (req, res) => {
  res.json({
    status: 'ok',
    version: process.env.APP_VERSION,
    region: process.env.AWS_REGION || 'unknown',
    configured: Object.keys(process.env).filter((k) => k.startsWith('FEATURE_')),
  });
});

module.exports = router;
