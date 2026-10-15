exports.highlight = (req, res) => {
  const text = res.locals.article.body;
~>  const marked = text.replace(new RegExp(req.body.term, 'gi'), (m) => `<mark>${m}</mark>`);
  res.send(marked);
};
