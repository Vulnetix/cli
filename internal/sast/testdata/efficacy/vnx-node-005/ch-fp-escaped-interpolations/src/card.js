import DOMPurify from "dompurify";
import { escapeHtml } from "./escape";

export function renderCard(el, user) {
  el.innerHTML = `<div class="card"><b>${escapeHtml(user.name)}</b></div>`;
  el.insertAdjacentHTML("afterbegin", DOMPurify.sanitize(user.bio));
  el.outerHTML = DOMPurify.sanitize(`<span>${user.status}</span>`);
}
