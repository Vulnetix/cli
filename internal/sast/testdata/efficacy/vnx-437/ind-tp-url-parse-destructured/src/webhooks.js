const url = require('url');

async function deliver(callbackUrl, event) {
  const { hostname } = url.parse(callbackUrl);
  if (hostname !== 'hooks.partner.io') {
    throw new Error(`webhook host ${hostname} is not allowed`);
  }
~>  const resp = await fetch(callbackUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(event),
  });
  return resp.ok;
}

module.exports = { deliver };
