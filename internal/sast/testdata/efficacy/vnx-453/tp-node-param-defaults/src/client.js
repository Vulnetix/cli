const https = require('https');

~>function createAgent({ keepAlive = true, rejectUnauthorized = false } = {}) {
  return new https.Agent({ keepAlive, rejectUnauthorized });
}

~>const setCookie = (res, name, value, secure = false, httpOnly = false) => {
  res.cookie(name, value, { secure, httpOnly });
};

class ApiClient {
~>  constructor(baseUrl, { strictSSL = false, timeout = 5000 } = {}) {
    this.baseUrl = baseUrl;
    this.strictSSL = strictSSL;
  }
}

module.exports = { createAgent, setCookie, ApiClient };
