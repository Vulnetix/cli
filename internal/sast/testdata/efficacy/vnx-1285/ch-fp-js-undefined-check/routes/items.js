const items = ['a', 'b', 'c'];

module.exports = (app) => {
  app.get('/items/:i', (req, res) => {
    const i = parseInt(req.params.i, 10);
    if (!Number.isInteger(i) || i < 0 || i >= items.length) {
      return res.sendStatus(404);
    }
    res.json(items[i]);
  });

  app.get('/rows', (req, res) => {
    const offset = Number(req.query.offset) || 0;
    res.json(items.slice(offset, offset + 10));
  });
};
