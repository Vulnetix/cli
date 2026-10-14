function remember(res, value) {
  res.cookie('prefs', value, {
~>    httpOnly: false,
    maxAge: 365 * 24 * 3600 * 1000,
  });
}

function issue(response, sid) {
~>  response.cookie('sid', sid, { httpOnly : false, secure: true });
}

module.exports = { remember, issue };
