'use strict';
const axios = require('axios');

// The webhook's response is never returned; the res.json() below belongs to
// the next handler, which relays nothing it fetched.
exports.fire = async function fire(req, res) {
  const { hookUrl } = req.body;
  await axios.post(hookUrl, { event: 'fired' });
  res.status(202).end();
};

exports.list = async function list(req, res) {
  const hooks = await store.listHooks(req.user.id);
  res.json(hooks);
};
