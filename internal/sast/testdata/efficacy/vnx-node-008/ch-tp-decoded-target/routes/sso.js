module.exports = function sso(app) {
  app.get("/sso/done", (req, res) => {
~>    res.redirect(decodeURIComponent(req.query.return_to));
  });
  app.get("/sso/back", (req, res) => {
    const dest = String(req.query.dest);
~>    return res.redirect(302, dest);
  });
};
