function stripScripts(html) {
~>  return html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, '');
}

function isSafeUrl(u) {
~>  return !/^javascript:/.test(u);
}

function stripHandlers(s) {
~>  const re = new RegExp('onerror\\s*=', 'g');
  return s.replace(re, '');
}

~>const clean = (s) => s.replace('<script>', '');

module.exports = { stripScripts, isSafeUrl, stripHandlers, clean };
