const passport = require("passport");
const { Strategy: LocalStrategy } = require("passport-local");
const logger = require("./logger");

passport.use(new LocalStrategy(verifyUser));
logger.info("passport strategies loaded", Object.keys(passport._strategies));
console.log("passport initialised", passport);

app.use(passport.initialize());
app.use(passport.session());
