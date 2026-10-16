// Bad pattern (do not do this):
//   const p = req.url;
//   if (p.startsWith('/admin')) deny();
//   const d = decodeURIComponent(p);
const HELP_TEXT = "Never test req.url with startsWith('/admin') before decodeURIComponent";

function helpPage(req, res) {
  res.type('text/plain').send(HELP_TEXT);
}

module.exports = helpPage;
