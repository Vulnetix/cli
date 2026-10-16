export function isApiRoute(url) {
  if (url.includes('/api/')) {
    return true;
  }
  return url.indexOf('/rpc/') !== -1;
}

export function isStatic(url) {
  if (!url.indexOf('/static/')) {
    return true;
  }
  const at = url.indexOf('?');
  if (at > -1) {
    return false;
  }
  return url.lastIndexOf('/') >= 0;
}
