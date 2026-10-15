function serve(req, res) {
  const raw = req.url.slice('/static/'.length);
~>  if (raw.includes('..')) {
    return res.writeHead(400).end();
  }
  const file = decodeURIComponent(raw);
  fs.createReadStream(path.join(ROOT, file)).pipe(res);
}
