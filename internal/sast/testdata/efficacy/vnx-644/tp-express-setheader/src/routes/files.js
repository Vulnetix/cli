const express = require('express');
const router = express.Router();

router.get('/files/:name', (req, res) => {
~>  res.setHeader('Content-Disposition', 'attachment; filename=' + req.params.name);
~>  res.set('X-Client-Tag', req.query.tag);
~>  res.header("X-Forwarded-User", req.headers['x-user']);
~>  res.append('Link', `<${req.query.next}>; rel="next"`);
  res.sendFile(resolve(req.params.name));
});

module.exports = router;
