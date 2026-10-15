export function showLink(el) {
  const q = new URLSearchParams(location.search).get('q');
~>  el.innerHTML = '<a href="/s?q=' + encodeURIComponent(q) + '">' + q + '</a>';
}
