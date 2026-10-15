module.exports = function mount(app) {
  app.get('/v1/quote', (req, res) => {
    const { callback } = req.query;
    const quote = JSON.stringify(nextQuote());
    res.set('Content-Type', 'application/javascript');
~>    res.send(callback + '(' + quote + ')');
  });
};
