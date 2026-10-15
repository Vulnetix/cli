function status(req, res) {
  switch (req.query.kind) {
    case 'json':
      res.json({ up: true });
      break;
    case 'text':
      res.send('up');
      break;
    default:
      res.sendStatus(400);
  }
}
