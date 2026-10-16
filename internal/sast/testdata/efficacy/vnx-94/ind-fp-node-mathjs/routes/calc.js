const { evaluate } = require('mathjs');

module.exports = function calc(app) {
  app.post('/calculate', (req, res) => {
    try {
      const result = evaluate(req.body.expression);
      res.json({ result });
    } catch (e) {
      res.status(400).json({ error: 'Invalid expression' });
    }
  });

  app.get('/version', (req, res) => {
    const fn = new Function('return 42');
    res.json({ v: fn(), note: 'eval(req.query.x) is never used here' });
  });
};
