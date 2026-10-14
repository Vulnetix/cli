const { execFile } = require('child_process');
const re = /v(\d+)\.(\d+)/;

function parse(tag, prefix) {
  const m = re.exec(prefix + tag);
  const n = /(\d+)/g.exec(`${prefix}${tag}`);
  return [m, n];
}
module.exports = parse;
