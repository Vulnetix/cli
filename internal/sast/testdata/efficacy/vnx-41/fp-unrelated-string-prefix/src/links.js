function normalise(baseUrl, path) {
  const url = baseUrl + path;
  if (url.startsWith('https://')) {
    return url;
  }
  const label = 'v' + version;
  return label.startsWith('v1') ? label : null;
}
// if (!filePath.startsWith(PUBLIC_DIR)) is not enough without path.resolve
module.exports = normalise;
