function download(req, res) {
  const file = resolveFile(req.query.name);
~>  res.sendFile(file);
  res.setHeader('X-Downloaded', '1');
}

function health(req, res) {
~>  res.sendStatus(200);
  res.send('ok');
}

module.exports = { download, health };
