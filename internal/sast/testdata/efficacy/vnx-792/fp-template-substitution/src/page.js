function render(tpl, subs) {
  let html = tpl.replace('<script id="subtitle"></script>', '<script id="subtitle">' + subs + '</script>');
  html = html.replace('<li></li></ol>', '</ol>');
  return html.replace('{{title}}', subs.title);
}
