const url = require('url');
const got = require('got');
const https = require('https');

async function notify(target, payload) {
  if (url.parse(target).hostname !== 'hooks.acme.example.com') {
    throw new Error('host not allowed');
  }
~>  await got.post(target, { json: payload });
}

function ping(link) {
  const { hostname, protocol } = url.parse(link);
  if (protocol !== 'https:' || !hostname.endsWith('.acme.example.com')) {
    return;
  }
~>  https.get(link, (r) => r.resume());
}

module.exports = { notify, ping };
