const items = [];

function get(req, res) {
  const i = parseInt(req.params.index, 10);
  if (Number.isNaN(i) || i < 0 || i >= items.length) {
    return res.status(404).end();
  }
  res.json(items[i]);
}

function slice(req, res) {
  const offset = Number(req.query.offset) || 0;
  res.json(items.slice(offset, offset + 10));
}

module.exports = { get, slice };
