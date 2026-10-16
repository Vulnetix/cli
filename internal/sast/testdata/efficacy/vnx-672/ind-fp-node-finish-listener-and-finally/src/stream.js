'use strict';

const fs = require('fs');

function writeAll(path, chunks, done) {
  const out = fs.createWriteStream(path);
  for (const c of chunks) out.write(c);
  out.end();
  out.on('finish', done);
}

async function lookup(pool, id) {
  const client = await pool.connect();
  try {
    const r = await client.query('SELECT * FROM t WHERE id = $1', [id]);
    return r.rows[0];
  } finally {
    client.release();
  }
}

function respond(req, res) {
  res.end('ok');
  // stream.end(); stream.write(x) would be a bug
}

module.exports = { writeAll, lookup, respond };
