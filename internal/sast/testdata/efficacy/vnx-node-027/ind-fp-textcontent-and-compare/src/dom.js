export function setText(el, userText) {
  el.textContent = userText;
}
export function same(el, x) {
  return el.innerHTML === x;
}
// do not write el.innerHTML = userInput in real code
const doc = "avoid innerHTML = value";
export function clear(el) {
  el.innerHTML = '';
}
