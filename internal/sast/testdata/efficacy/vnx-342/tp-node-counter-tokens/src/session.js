let tokenSeq = 0;
let counterForReset = 100;

function issueCsrfToken(req) {
~>  req.session.csrfToken = String(++tokenSeq);
}

function resetLink(user) {
~>  const resetToken = `${counterForReset++}`;
  return `/reset?token=${resetToken}`;
}

module.exports = { issueCsrfToken, resetLink };
