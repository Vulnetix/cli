const DOMPurify = require('dompurify');

const SCRIPT_RE = /<script\b[^>]*>[\s\S]*?<\/script>/gi;

function stripScripts(html) {
  return html.replace(SCRIPT_RE, '');
}

function isDangerousUrl(href) {
  const normalized = String(href).trim().toLowerCase();
  return normalized.startsWith('javascript:') || normalized.includes('vbscript:');
}

function hasInlineHandler(markup) {
  return new RegExp('onerror\\s*=', 'i').test(markup);
}

function render(html) {
  return DOMPurify.sanitize(stripScripts(html));
}

module.exports = { stripScripts, isDangerousUrl, hasInlineHandler, render };
