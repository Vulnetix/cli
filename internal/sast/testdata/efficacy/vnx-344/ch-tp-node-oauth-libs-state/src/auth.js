const passport = require("passport");
const { AuthorizationCode } = require("simple-oauth2");

const client = new AuthorizationCode(config);

function startLogin(req, res) {
  const authorizationUri = client.authorizeURL({
    redirect_uri: "https://app.example.com/callback",
    scope: "openid profile",
~>    state: "3f9a7c21",
  });
  res.redirect(authorizationUri);
}

app.get(
  "/auth/google",
~>  passport.authenticate("google", { scope: ["profile"], state: "login-flow" })
);

async function oidc(req, res, issuerClient) {
~>  const url = issuerClient.authorizationUrl({ scope: "openid email", state: "fixedstate" });
  res.redirect(url);
}
