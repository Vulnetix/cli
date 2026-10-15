const PAGE = 20;

async function list(req, res) {
  const page = parseInt(req.query.page, 10) || 0;
  const rows = await db.collection('orders').find().skip(page * PAGE).limit(PAGE).toArray();
  res.json(rows);
}

module.exports = { list };
