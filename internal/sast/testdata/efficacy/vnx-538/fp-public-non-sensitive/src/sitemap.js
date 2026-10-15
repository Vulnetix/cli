const fs = require('fs');

function writeSitemap(xml, tokens) {
  fs.writeFileSync('public/sitemap.xml', xml);
  const count = tokens.length;
  fs.writeFileSync('public/stats.txt', String(count));
}
