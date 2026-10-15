const escapeHtml = require('escape-html');

function strip(html) {
  return html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
}

function isSafeUrl(u) {
  return !/^\s*javascript:/i.test(u);
}

const handlers = new RegExp('on(error|load)\\s*=', 'gi');

function render(name) {
  return '<p>' + escapeHtml(name) + '</p>';
}

module.exports = { strip, isSafeUrl, handlers, render };
