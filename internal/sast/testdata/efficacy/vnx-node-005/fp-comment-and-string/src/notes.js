// Never write el.innerHTML = userInput; use textContent.
/* dangerouslySetInnerHTML={{ __html: body }} is banned */
const rule = "el.innerHTML = value is unsafe";
export default rule;
