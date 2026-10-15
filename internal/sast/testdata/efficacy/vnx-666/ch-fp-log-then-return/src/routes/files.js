router.get('/files/:name', (req, res) => {
  if (!allowed(req.params.name)) {
    res.status(403).send('forbidden');
    logger.warn('denied %s', req.params.name);
    return;
  }
  fs.readFile(path.join(ROOT, req.params.name), (err, buf) => {
    if (err) {
      res.status(500).end();
      return;
    }
    res.send(buf);
  });
});

router.get('/cache', (req, res) => {
  if (cache.has(req.query.k)) {
    res.json(cache.get(req.query.k));
  } else if (req.query.fallback) {
    res.json({});
  }
  stats.hit(req.query.k);
});
