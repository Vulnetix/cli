const SPINNER_SVG = '<svg class="spin"></svg>';

export function reset(el, other) {
  el.innerHTML = '';
  el.innerHTML = "<p>Loading</p>";
  el.innerHTML = SPINNER_SVG;
  const saved = el.innerHTML;
  if (el.innerHTML === '') return saved;
  el.innerHTML = other.innerHTML;
  el.innerHTML = Icons.CARET_SPACE;
  el.innerHTML = document.getElementById(other.id).innerHTML;
}
