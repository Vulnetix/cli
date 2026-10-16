function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function slug(title) {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

// do not write html.replace('<script>', '') here
const DOC = "html.replace('<script>', '') is not a sanitiser";

module.exports = { escapeHtml, slug, DOC };
