// if (url.startsWith('https://cdn.acme-media.com')) fetch(url);
/*
 * Do not write: if (url.includes('acme.example.com')) res.redirect(url);
 */
function explain(url) {
  if (url.startsWith('https://cdn.acme-media.com')) {
    console.log("then call fetch(url) after parsing it");
  }
  return 'url.startsWith("https://cdn.acme-media.com") && fetch(url)';
}

module.exports = { explain };
