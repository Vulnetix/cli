app.get('/healthz', (req, res) => {
  res.json({ status: 'ok', version: process.env.APP_VERSION, region: process.env['REGION'] });
});
