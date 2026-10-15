export function setStatus(el, text) {
  el.textContent = text;
  el.innerText = `Status: ${text}`;
  el.setAttribute("title", text);
  el.innerHTML = "";
  el.innerHTML = '<span class="spinner"></span>';
  const copy = el.innerHTML.trim();
  document.title = text;
  return copy;
}
