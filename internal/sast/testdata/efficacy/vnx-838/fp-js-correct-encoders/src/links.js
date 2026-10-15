function link(q) {
  results.innerHTML = '<a href="/search?q=' + encodeURIComponent(q) + '">again</a>';
  img.innerHTML = `<img src="/avatar/${encodeURIComponent(user)}.png">`;
  out.textContent = encodeURIComponent(q);
  window.location = '/search?q=' + encodeURIComponent(q);
  const url = new URL('/x?q=' + encodeURIComponent(q), base);
  results.innerHTML = '<h2>' + escapeHtml(q) + '</h2>';
}
