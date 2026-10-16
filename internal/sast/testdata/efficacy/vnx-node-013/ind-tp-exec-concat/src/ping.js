const { exec } = require('child_process');

app.get('/ping', (req, res) => {
~>  exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    res.type('text/plain').send(stdout);
  });
});
