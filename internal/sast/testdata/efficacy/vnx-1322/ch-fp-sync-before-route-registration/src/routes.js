const fs = require('fs');

function registerRoutes(app) {
  const banner = fs.readFileSync('./banner.txt', 'utf8');
  const config = JSON.parse(fs.readFileSync('./routes.json', 'utf8'));
  app.get('/', (req, res) => {
    res.send(banner + config.title);
  });
}

module.exports = registerRoutes;
