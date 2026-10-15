const ALLOWED_CALLBACKS = new Set(['renderWidget', 'onWidgetData']);

app.get('/widget.js', (req, res) => {
  const cb = req.query.callback;
  if (!ALLOWED_CALLBACKS.has(cb)) {
    return res.status(400).end();
  }
  res.type('js').send(cb + '(' + JSON.stringify(widgetData()) + ')');
});

app.get('/widget2.js', (req, res) => {
  const name = req.query.cb;
  if (name !== 'loadWidget') return res.sendStatus(400);
  res.send(name + '(' + JSON.stringify(widgetData()) + ')');
});
