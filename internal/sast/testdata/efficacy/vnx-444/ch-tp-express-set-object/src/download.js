function sendFile(res, buf) {
  res.set({
    "Content-Type": "application/zip",
    "Content-Length": buf.length,
~>    "Transfer-Encoding": "chunked",
  });
  res.end(buf);
}

module.exports = { sendFile };
