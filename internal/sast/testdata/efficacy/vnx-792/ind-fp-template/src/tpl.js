function render(tpl, name) {
  return tpl.replace('{{name}}', '<b>' + name + '</b>');
}
function trimTitle(t) { return t.replace('Mr', 'Dr'); }
module.exports = { render, trimTitle };
