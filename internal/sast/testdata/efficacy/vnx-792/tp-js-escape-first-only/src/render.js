function escapeHtml(text) {
~>  return text.replace('<', '&lt;')
~>             .replace(">", "&gt;")
~>             .replace('&', '&amp;');
}

function attr(v) {
~>  return '"' + v.replace('"', '&quot;') + '"';
}
