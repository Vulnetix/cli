// Shapes VNX-NODE-005 and VNX-NODE-012 used to report too; VNX-NODE-027 owns them.
export function flash(node, msg) {
~>  node["innerHTML"] = msg;
~>  node['outerHTML'] = `<p class="flash">${msg}</p>`;
}

export function searchLink(el) {
  const q = new URLSearchParams(location.search).get('q');
~>  el.innerHTML = '<a href="/s?q=' + encodeURIComponent(q) + '">' + q + '</a>';
}

export function legacyWelcome(box) {
~>  box.innerHTML = 'Hello ' + unescape(location.search.substring(6));
}

export function fromHash(panel) {
~>  panel.innerHTML = decodeURIComponent(location.hash.slice(1));
}

export async function comments(list) {
  const res = await fetch('/api/comments');
  for (const c of await res.json()) {
~>    list.innerHTML += `<li><b>${c.author}</b>: ${c.text}</li>`;
  }
}

export function encodedOnly(el, q) {
  el.innerHTML = '<a href="/s?q=' + encodeURIComponent(q) + '">search</a>';
  el.innerHTML = `<span>${escapeHtml(q)}</span>`;
  node["innerHTML"] = "";
}
