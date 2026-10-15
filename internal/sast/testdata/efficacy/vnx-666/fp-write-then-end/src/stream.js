function streamRows(req, res) {
  res.setHeader('Content-Type', 'text/csv');
  res.status(200);
  for (const row of rows) {
    res.write(row.join(',') + '\n');
  }
  res.end();
}

function finish(req, res) {
  res.json({ ok: true });
  logger.info('sent response');
  metrics.increment('ok');
}
