async function verifyTurnstile(token, ip) {
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET, response: token, remoteip: ip }),
  });
  const data = await r.json();
  return data.success === true;
}

module.exports = { verifyTurnstile };
