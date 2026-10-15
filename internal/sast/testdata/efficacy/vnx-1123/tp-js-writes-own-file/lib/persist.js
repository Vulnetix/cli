const fs = require('fs');

function persist(extra) {
  const src = fs.readFileSync(__filename, 'utf8');
~>  fs.writeFileSync(__filename, src + extra);
~>  fs.appendFile(process.argv[1], '\n// seen', () => {});
}

module.exports = { persist };
