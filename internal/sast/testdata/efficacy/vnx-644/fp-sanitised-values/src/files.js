const contentDisposition = require('content-disposition');

router.get('/files/:name', (req, res) => {
  res.setHeader('Content-Disposition', contentDisposition(req.params.name));
  res.set('X-Page', String(parseInt(req.query.page, 10)));
  res.setHeader('X-Name', encodeURIComponent(req.query.name));
  const tag = req.query.tag.replace(/[\r\n]/g, '');
  res.set('X-Tag', tag);
  res.setHeader('Content-Type', 'application/json');
  res.sendFile(safePath(req.params.name));
});
