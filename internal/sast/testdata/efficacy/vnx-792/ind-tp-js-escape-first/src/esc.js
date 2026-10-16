function escapeHtml(text) {
~>  return text.replace('<', '&lt;')
~>             .replace(">", "&gt;");
}
module.exports = escapeHtml;
