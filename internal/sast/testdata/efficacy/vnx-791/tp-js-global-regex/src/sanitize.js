function clean(input) {
~>  return input.replace(/<script>/gi, '');
}

function cleanHref(href) {
~>  return href.replace(/javascript:/g, "");
}

function cleanPath(p) {
~>  return p.replace(/\.\.\//g, '');
}
