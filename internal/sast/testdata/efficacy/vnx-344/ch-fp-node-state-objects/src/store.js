const passport = require("passport");

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"], state: true }));

function startLogin(req, res, client) {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  const uri = client.authorizeURL({
    redirect_uri: "https://app.example.com/callback",
    scope: "openid",
    state: state,
  });
  res.redirect(uri);
}

const ticket = { id: 4, state: "open", owner: "ops" };
const machine = createMachine({ initial: "idle", state: "loading" });
