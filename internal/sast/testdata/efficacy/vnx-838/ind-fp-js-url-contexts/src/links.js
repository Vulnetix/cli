function a(el, id) {
  el.innerHTML = '<a href="/item?id=' + encodeURIComponent(id) + '">open</a>';
}

function b(q) {
  window.location = '/search?q=' + encodeURIComponent(q);
}

function c(el, q) {
  el.textContent = 'Results for ' + q;
  fetch('/api?x=' + encodeURIComponent(q));
}
