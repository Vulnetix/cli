import { marked } from 'marked';

export function renderComment(el, body) {
  el.innerHTML = marked.parse(body); // TODO: XSS risk, body is user-authored markdown
}
