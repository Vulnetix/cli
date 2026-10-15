const axios = require('axios');

module.exports.testWebhook = async (req, res) => {
  const target = req.body.callbackUrl;
  try {
~>    const r = await axios({
      method: 'post',
      url: target,
      data: { ping: true },
      timeout: 5000,
    });
    res.json({ status: r.status });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
};
