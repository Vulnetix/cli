const cors = require('cors');
const allowed = ['https://app.acme.io', 'https://admin.acme.io'];

module.exports = cors({
  origin: (origin, cb) => cb(null, !origin || allowed.includes(origin)),
  credentials: true,
});
