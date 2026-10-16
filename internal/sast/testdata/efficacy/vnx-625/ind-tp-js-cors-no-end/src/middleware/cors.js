const cors = require('cors');

~>const ALLOWED_ORIGIN = /^https:\/\/([a-z0-9-]+\.)?acmecorp\.com/;

module.exports = cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGIN.test(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
});
