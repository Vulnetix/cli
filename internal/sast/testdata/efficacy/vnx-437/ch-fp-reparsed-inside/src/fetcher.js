async function load(u) {
  if (u.startsWith('https://cdn.acme-media.com')) {
    const parsed = new URL(u);
    if (parsed.hostname === 'cdn.acme-media.com') {
      return fetch(u);
    }
  }
  return null;
}

module.exports = { load };
