const fs = require('fs');

app.get('/download', (req, res) => {
~>  fs.readFile(req.query.file, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.type('text/plain').send(data);
  });
});
