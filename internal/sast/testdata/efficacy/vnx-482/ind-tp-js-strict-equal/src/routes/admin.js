'use strict';

function revoke(req, res) {
  const session = req.session;
~>  session.isAdmin === false;
  res.status(204).end();
}

module.exports = { revoke };
