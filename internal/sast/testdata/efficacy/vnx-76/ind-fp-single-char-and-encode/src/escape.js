'use strict';

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function slug(s) {
  return s.replace(/;/g, '').replace(/\s+/g, '_');
}

function noAnd(cmd) {
  return cmd.replace('&&', ' and ');
}

// Do not write html.replace(/<iframe/g, '') here: it can be rebuilt.
const note = "html.replace('<iframe', '') is unsafe";

module.exports = { escapeHtml, slug, noAnd, note };
