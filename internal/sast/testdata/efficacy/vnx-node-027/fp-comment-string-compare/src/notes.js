// el.innerHTML = userInput is dangerous; use textContent.
/*
 * container.innerHTML = location.hash;
 */
const warning = "never write el.innerHTML = value";
const isSame = node.innerHTML == other;
module.exports = { warning, isSame };
