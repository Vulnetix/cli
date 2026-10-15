const TRUSTED = 'https://portal.example.com';

function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', TRUSTED);
  res.setHeader('Access-Control-Allow-Origin', 'https://portal.example.com');
  res.end('ok');
}

async function callUpstream(url) {
  const xhr = new XMLHttpRequest();
  xhr.open('GET', url);
  xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
  return fetch(url, {
    headers: { 'Access-Control-Allow-Origin': '*' },
  });
}

const socketOptions = { origin: true };

module.exports = { handler, callUpstream, socketOptions };
