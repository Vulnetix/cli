'use strict';

function stripEmbeds(html) {
~>  return html.replace(/<iframe/gi, '');
}

function stripObjects(html) {
~>  const cleaned = html.replaceAll('<object', '');
  return cleaned;
}

module.exports = { stripEmbeds, stripObjects };
