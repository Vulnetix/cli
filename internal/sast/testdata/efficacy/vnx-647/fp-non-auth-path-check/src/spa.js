app.use((req, res, next) => {
  if (req.path.startsWith('/static')) {
    res.set('Cache-Control', 'public, max-age=31536000');
  }
  if (req.path.startsWith('/api')) return next();
  res.sendFile(indexHtml);
});

app.use((req, res, next) => {
  logger.info('request ' + req.path);
  if (req.url === '/health') return res.send('ok');
  next();
});
