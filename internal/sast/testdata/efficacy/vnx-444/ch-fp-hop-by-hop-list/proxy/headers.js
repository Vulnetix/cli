const HOP_BY_HOP = [
  "connection",
  "keep-alive",
  "transfer-encoding",
  "content-length",
  "upgrade",
];

function strip(headers) {
  for (const h of HOP_BY_HOP) delete headers[h];
  return headers;
}

module.exports = strip;
