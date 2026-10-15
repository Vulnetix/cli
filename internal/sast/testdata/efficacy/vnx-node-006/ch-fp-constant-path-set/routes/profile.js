const _ = require("lodash");

module.exports = function update(req, res) {
  const user = res.locals.user;
  _.set(user, "profile.displayName", req.body.displayName);
  _.set(user, ["profile", "timezone"], req.body.timezone);
  _.set(user, `profile.locale`, req.body.locale);
  res.json({ user });
};
