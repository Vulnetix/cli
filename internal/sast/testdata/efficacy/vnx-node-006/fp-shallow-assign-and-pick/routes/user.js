const _ = require('lodash');

exports.update = (req, res) => {
  const copy = Object.assign({}, req.body);
  const user = _.merge(res.locals.user, _.pick(req.body, ['name', 'email']));
  const path = _.get(user, req.query.field);
  res.json({ copy, user, path });
};
