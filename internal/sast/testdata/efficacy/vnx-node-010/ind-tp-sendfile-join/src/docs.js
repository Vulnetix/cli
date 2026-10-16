const path = require('path');

router.get('/docs/:name', (req, res) => {
~>  res.sendFile(path.join(__dirname, 'docs', req.params.name));
});
