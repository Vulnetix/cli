import { escapeHtml } from './util';

export function item(li, user) {
  li.innerHTML = escapeHtml(user.name);
  // li.innerHTML = user.name;  (old, unsafe)
}
