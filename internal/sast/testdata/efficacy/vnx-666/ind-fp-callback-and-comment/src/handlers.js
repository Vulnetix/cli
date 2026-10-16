const handlers = {
  ping(req, res) {
    res.send('pong');
  },
  health(req, res) {
    res.json({ ok: true });
  },
};

app.get('/legacy', (req, res) => {
  db.query('select 1', (err, rows) => {
    if (err) {
      res.status(500).send('db error');
    } else {
      res.json(rows);
    }
  });
});

// Do not do: res.status(404).json({}) and then res.json(user) again
const note = "res.send('x'); res.send('y');";
module.exports = handlers;
