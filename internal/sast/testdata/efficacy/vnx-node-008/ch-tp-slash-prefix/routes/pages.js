module.exports = function pages(router) {
  router.get("/go", (req, res) => {
~>    res.redirect("/" + req.query.page);
  });
  router.get("/jump", (req, res) => {
~>    res.redirect(`/${req.query.to}`);
  });
};
