module.exports = function files(router) {
  router.get("/files/:id", (req, res) => {
    res.redirect(`/download/${req.params.id}`);
  });
  router.get("/legacy", (req, res) => {
    res.redirect(301, req.baseUrl + "/v2" + req.path);
  });
};
