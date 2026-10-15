function fmt(v, url) {
  const ver = v.replace('v', '');
  const u = url.replace('/', '');
  const ellipsis = text => text.replace('...', '…');
  return ver + u + ellipsis('a...');
}
