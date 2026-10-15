let lastCsrf = 5000;

function issueCsrf(req) {
~>  const csrfToken = lastCsrf + Math.floor(Math.random() * 100);
  lastCsrf = csrfToken;
  req.session.csrf = csrfToken;
}

function inviteCode(prev) {
~>  const invite_code = String(prev + Math.random() * 10);
  return invite_code;
}

module.exports = { issueCsrf, inviteCode };
