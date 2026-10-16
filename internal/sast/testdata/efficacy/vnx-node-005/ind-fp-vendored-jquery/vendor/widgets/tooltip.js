function show(target, markup) {
  target.insertAdjacentHTML('beforeend', `<div class="tip">${markup}</div>`);
  document.write("<i>" + markup + "</i>");
}
