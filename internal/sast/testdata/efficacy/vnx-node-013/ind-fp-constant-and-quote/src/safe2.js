const { exec } = require('child_process');
const quote = require('shell-quote').quote;

function nightly() {
  exec('tar czf /backup/site.tgz /srv/site', () => {});
}
app.get('/ls', (req, res) => {
  exec('ls -la ' + quote([req.query.dir]), (e, o) => res.send(o));
});
