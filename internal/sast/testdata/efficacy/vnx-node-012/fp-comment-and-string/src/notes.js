// el.innerHTML = location.hash is a DOM XSS sink.
/* document.write("<p>" + document.referrer + "</p>") */
const tip = "Prefer textContent over el.innerHTML = location.search";
export default tip;
