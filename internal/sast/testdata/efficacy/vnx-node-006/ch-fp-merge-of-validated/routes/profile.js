const _ = require("lodash");
const { profileSchema } = require("../schemas");

module.exports = async function update(req, res) {
  const { error, value } = profileSchema.validate(req.body, { stripUnknown: true });
  if (error) return res.status(400).json(error.details);
  const merged = _.merge(req.user.profile, value);
  const label = _.get(req.body, "label", "none");
  res.json({ merged, label });
};
