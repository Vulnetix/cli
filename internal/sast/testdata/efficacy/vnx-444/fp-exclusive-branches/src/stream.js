function frame(res, size) {
  if (size !== undefined) {
    res.setHeader('Content-Length', size);
  } else {
    res.setHeader('Transfer-Encoding', 'chunked');
  }
}
module.exports = frame;
