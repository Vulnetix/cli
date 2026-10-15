function trimSlashes(s) {
  return s.replace(/^\/+|\/+$/g, '');
}

function dots(v) {
  return v.replace(/\.+/g, '.');
}
