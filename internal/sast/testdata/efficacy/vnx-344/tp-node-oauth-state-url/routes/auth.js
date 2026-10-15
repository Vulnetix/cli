const router = require("express").Router();

router.get("/login", (req, res) => {
  const url =
~>    "https://github.com/login/oauth/authorize?client_id=" + process.env.GH_CLIENT + "&response_type=code&state=fixedstate";
  res.redirect(url);
});

router.get("/login2", (req, res) => {
~>  res.redirect(`https://idp.example.com/oauth2/authorize?response_type=code&client_id=${cid}&state=abc&redirect_uri=${cb}`);
});

module.exports = router;
