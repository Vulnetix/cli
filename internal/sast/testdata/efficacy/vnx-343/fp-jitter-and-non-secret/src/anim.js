function wobble(el, prev) {
  const position = prev + Math.random() * 4;
  el.style.left = position + "px";
  const sessionTimeout = lastTimeout + Math.floor(Math.random() * 30);
  return sessionTimeout;
}
module.exports = wobble;
