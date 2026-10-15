export function reset(el, counter) {
  el.innerHTML = null;
  counter.innerHTML = 0;
  el.innerHTML = '';
  el.textContent = el.dataset.label;
  el.insertAdjacentText("beforeend", el.dataset.label);
}
