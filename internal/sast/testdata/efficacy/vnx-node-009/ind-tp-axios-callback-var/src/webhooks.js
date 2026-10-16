const axios = require('axios');

async function notify(req, res) {
  const callback = req.body.callbackUrl;
  const payload = { event: 'job.done', id: req.body.jobId, at: Date.now() };
~>  await axios.post(callback, payload, { timeout: 3000 });
  res.sendStatus(204);
}

module.exports = { notify };
