router.get('/cb', (req, res) => {
  db.query(sql, (err, rows) => {
    if (err) {
      res.status(500).send(err.message);
    } else {
      res.json(rows);
    }
  });
});

router.get('/sw', (req, res) => {
  switch (req.query.kind) {
    case 'a':
      res.send('a');
      break;
    default:
      res.send('other');
  }
});

const handlers = {
  ok: (req, res) => {
    res.send('ok');
  },
  fail: (req, res) => {
    res.status(500).send('fail');
  },
};
