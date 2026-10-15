const fs = require('fs');
const path = require('path');

function routes(router) {
  router.get('/static/:name', (req, res) => {
    res.sendFile(req.params.name, { root: path.join(__dirname, 'public') });
  });
  router.get('/avatar', (req, res) => {
    fs.createReadStream(path.join(__dirname, 'avatars', path.basename(req.query.f))).pipe(res);
  });
  router.post('/log', (req, res) => {
    fs.appendFile('/var/log/app.log', req.body.msg, () => res.end());
  });
  router.get('/config', (req, res) => {
    res.send(fs.readFileSync(path.join(__dirname, 'config.json')));
  });
}
module.exports = routes;
