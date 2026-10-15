const axios = require('axios');

const ALLOWED_HOSTS = new Set(['hooks.slack.com', 'api.github.com']);

exports.deliver = async (req, res) => {
  const url = new URL(req.body.url);
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    return res.status(400).send('host not allowed');
  }
  await axios.post(url.toString(), req.body.payload);
  res.sendStatus(204);
};
