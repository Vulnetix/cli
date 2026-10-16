const contentDisposition = require('content-disposition');
app.get('/dl/:name', (req, res) => {
  res.setHeader('Content-Disposition', contentDisposition(req.params.name));
  res.set('X-Name', encodeURIComponent(req.query.n));
  res.set('X-Page', parseInt(req.query.page, 10));
  res.set('X-Clean', String(req.query.c).replace(/[\r\n]/g, ''));
  res.set('X-App', 'portal');
  res.send('ok');
});
