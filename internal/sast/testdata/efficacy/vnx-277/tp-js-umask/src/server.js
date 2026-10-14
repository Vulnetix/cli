const fs = require('fs');

function start(dir) {
~>  process.umask(0);
  fs.mkdirSync(dir, { recursive: true });
}

function spool() {
~>  process.umask(0o000);
  fs.writeFileSync('/var/spool/app/queue', '');
}

module.exports = { start, spool };
