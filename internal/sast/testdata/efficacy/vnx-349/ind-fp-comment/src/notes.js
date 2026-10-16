// Never write Object.assign(req.user, req.body): the body overwrites the role.
const warning = "Object.assign(session, req.body) is a mass-assignment bug";

function describe() {
  return warning;
}

module.exports = { describe };
