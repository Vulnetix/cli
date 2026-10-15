export function reset(el) {
  el.innerHTML = '';
  el.innerHTML = "<p class=\"loading\">Loading...</p>";
  const before = el.innerHTML;
  if (el.innerHTML === '') {
    console.log(before);
  }
}
