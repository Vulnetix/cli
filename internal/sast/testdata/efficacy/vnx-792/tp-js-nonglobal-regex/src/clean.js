function clean(s) {
~>  return s.replace(/<script[^>]*>/i, '');
}

function esc(s) {
~>  return s.replace(/</, '&lt;');
}
