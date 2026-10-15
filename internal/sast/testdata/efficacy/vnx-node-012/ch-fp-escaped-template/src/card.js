function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

export function card(el, user) {
  el.innerHTML = `<b>${escapeHtml(user.name)}</b>`;
}
