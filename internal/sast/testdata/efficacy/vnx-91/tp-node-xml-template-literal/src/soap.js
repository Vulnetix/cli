const axios = require('axios');

async function lookup(req, res) {
~>  const body = `<?xml version="1.0"?><soap:Envelope><soap:Body><GetUser><name>${req.body.name}</name></GetUser></soap:Body></soap:Envelope>`;
  const account = req.query.account;
~>  const filter = '<account>' + account + '</account>';
  const r = await axios.post(SOAP_URL, body + filter, { headers: { 'Content-Type': 'text/xml' } });
  res.send(r.data);
}

module.exports = lookup;
