const fs = require('fs');
const path = require('path');

function buildSitemap(urls) {
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...urls.map((u) => `  <url><loc>${u}</loc></url>`),
    '</urlset>',
  ].join('\n');
  fs.writeFileSync(path.join(__dirname, '..', 'public', 'sitemap.xml'), xml);
}

module.exports = buildSitemap;
