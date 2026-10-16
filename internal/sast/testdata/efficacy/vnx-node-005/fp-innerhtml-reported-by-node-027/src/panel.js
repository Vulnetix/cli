// An innerHTML/outerHTML assignment is reported by VNX-NODE-027, not here.
export function showPanel(panel, card, msg) {
  panel.innerHTML = decodeURIComponent(location.hash.slice(1));
  card.outerHTML = `<div class="card">${msg}</div>`;
  panel["innerHTML"] = msg;
  panel.innerHTML += '<li>' + msg + '</li>';
}
