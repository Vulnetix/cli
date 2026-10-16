import { escape } from 'lodash';

function a(el, q) {
  el.innerHTML = '<h2>Results for ' + escapeHtml(q) + '</h2>';
}

function b(el, q) {
  el.innerHTML = `<p>${escape(q)}</p>`;
}
