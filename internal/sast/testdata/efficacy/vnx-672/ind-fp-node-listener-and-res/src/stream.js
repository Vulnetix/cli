const fs = require('fs');

function writeAll(path, lines, cb) {
  const out = fs.createWriteStream(path);
  for (const l of lines) out.write(l + '\n');
  out.end();
  out.on('finish', () => cb(null));
}

function handler(req, res) {
  res.write('part one');
  res.end();
}

async function ok(pool) {
  const client = await pool.connect();
  try {
    await client.query('select 1');
  } finally {
    client.release();
  }
  const c2 = await pool.connect();
  await c2.query('select 2');
  c2.release();
}
module.exports = { writeAll, handler, ok };
