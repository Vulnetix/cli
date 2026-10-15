const { safeRedirectPath } = require("../lib/redirects");

module.exports = function (router) {
  router.get("/account", (req, res) => {
    if (!req.user) {
      return res.redirect(req.baseUrl + "/login");
    }
    res.redirect(safeRedirectPath(req.query.next));
  });
  router.get("/u/:id", (req, res) => res.redirect(`/users/${encodeURIComponent(req.params.id)}`));
};
