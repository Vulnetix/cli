var crypto = require("crypto");
var bcrypt = require("bcryptjs");

function SessionHandler(db) {
    this.handleLogin = function(req, res, next) {
        var user = db.findUser(req.body.userName);
~>        var key = crypto.pbkdf2Sync(req.body.password, user.salt, 210000, 64, "sha512");
~>        if (!bcrypt.compareSync(req.body.password, user.hash)) {
            return res.status(401).send("bad credentials");
        }
        req.session.key = key.toString("hex");
        next();
    };
}

module.exports = SessionHandler;
