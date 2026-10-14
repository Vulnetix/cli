// Never call eval(userInput) here.
/* new Function(body) was removed in v2 */
const xss = 'javascript:eval(document.body.innerHTML)';
const msg = "do not use new Function(code) on input";
module.exports = { xss, msg };
