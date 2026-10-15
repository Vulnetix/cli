function stripTraversal(p) {
  let out = p;
  do {
    out = out.replace('../', '');
  } while (out.includes('../'));
  return out;
}

function normaliseNewlines(s) {
  return s.replace(/\r\n/g, '\n').replace('\t', '  ');
}

function dotsToDash(s) {
  // collapse "a..b" to "a-b"
  return s.replace('..', '-');
}

const help = 'Never call name.replace("../", "") to sanitise a path';
// name.replace("../", "") is not a sanitiser

module.exports = { stripTraversal, normaliseNewlines, dotsToDash, help };
