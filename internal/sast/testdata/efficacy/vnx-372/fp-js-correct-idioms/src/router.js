function isApi(url) {
  if (url.indexOf('/api/') !== -1) {
    return true;
  }
  if (url.indexOf('/v2/') > -1 || ~url.indexOf('/v3/')) {
    return true;
  }
  // !s.indexOf(x) is the starts-with idiom: true only at index 0
  if (!url.indexOf('/static/')) {
    return false;
  }
  const i = url.indexOf('?');
  return i >= 0 ? url.slice(0, i) : url;
}

async function find(client, q) {
  if (client.search(q)) {
    return true;
  }
  return url.includes('/api/');
}
