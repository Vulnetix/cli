// Server-side request forgery in JavaScript is reported by VNX-NODE-009,
// not by this rule, so the same request is not reported twice.
const axios = require('axios');

exports.thumbnail = async (req, res) => {
  const source = req.query.src;
  await axios.get(source, { responseType: 'arraybuffer' });
  res.sendStatus(202);
};
