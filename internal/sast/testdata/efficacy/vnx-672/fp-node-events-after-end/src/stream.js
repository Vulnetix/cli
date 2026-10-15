function finish(stream, cb) {
  stream.end();
  stream.on('finish', cb);
  stream.once('error', cb);
}

function handler(req, res) {
  res.end();
  logger.info('done');
}

function recycle(pool) {
  const client = pool.connect();
  client.release();
  return pool.query('SELECT 1');
}
