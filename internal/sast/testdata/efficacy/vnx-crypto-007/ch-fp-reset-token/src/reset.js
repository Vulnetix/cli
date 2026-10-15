const crypto = require("crypto");
function store(user, passwordResetToken) {
  user.resetHash = crypto.createHash("sha256").update(passwordResetToken).digest("hex");
}
module.exports = { store };
