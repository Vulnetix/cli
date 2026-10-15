const SUPPORTED = ['en', 'fr', 'de'];

module.exports = async function messages(req, res) {
  const lang = req.query.lang;
  if (!SUPPORTED.includes(lang)) {
    return res.status(400).end();
  }
  const mod = await import(`./locales/${lang}.js`);
  res.json(mod.default);
};
