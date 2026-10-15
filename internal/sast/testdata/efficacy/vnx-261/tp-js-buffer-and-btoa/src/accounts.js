const db = require('./db');

async function createAccount(req, res) {
  const { email } = req.body;
~>  const encoded = Buffer.from(req.body.password).toString('base64');
  await db.users.insert({ email, password: encoded });
  res.status(201).end();
}

function rememberLogin(form) {
~>  localStorage.setItem('pw', btoa(form.userPassword));
}

module.exports = { createAccount, rememberLogin };
