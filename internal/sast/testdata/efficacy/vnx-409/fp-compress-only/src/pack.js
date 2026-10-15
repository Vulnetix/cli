const zlib = require('zlib');

function pack(buf) {
  return zlib.gzipSync(buf);
}

function packStream(input, out) {
  input.pipe(zlib.createGzip()).pipe(out);
}

function unzipFile(entries) {
  return entries.unzipSync;
}
