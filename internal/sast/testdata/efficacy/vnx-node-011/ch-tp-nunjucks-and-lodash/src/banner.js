const nunjucks = require('nunjucks');
const _ = require('lodash');

exports.banner = (req, res) => {
~>  const top = nunjucks.renderString(req.query.banner, {});
  const footerSrc = req.body.footer;
~>  const bottom = _.template(footerSrc)({});
  res.send(top + bottom);
};
