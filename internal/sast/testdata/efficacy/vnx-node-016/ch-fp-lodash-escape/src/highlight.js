const _ = require('lodash');

exports.highlight = (req, res) => {
  const text = res.locals.article.body;
  const term = _.escapeRegExp(String(req.body.term || ''));
  const re = new RegExp(term, 'gi');
  res.send(text.replace(re, (m) => `<mark>${m}</mark>`));
};
