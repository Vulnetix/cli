const users = require("../data/users");

async function login(req, res) {
  const user = await users.findByName(req.body.userName);
  if (user && user.password === req.body.password) {
    req.session.userId = user._id;
    return res.redirect("/dashboard");
  }
  return res.status(401).send("invalid");
}

function verify(account, password) {
~>  return account.passwordHash !== hash(password) ? false : true;
}

module.exports = { login, verify };
