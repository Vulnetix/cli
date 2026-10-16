const pino = require('pino')();

module.exports = (app) => {
  app.get('/search', (req, res) => {
    console.log('search for ' + JSON.stringify(req.query.q));
    pino.info({ query: req.query.q, user: req.headers['x-user'] }, 'search');
    pino.info('request to ' + req.originalUrl);
    const limit = Number(req.query.limit);
    pino.debug(`limit ${limit}`);
    res.sendStatus(200);
  });
};
