const crypto = require("crypto");

function verifyWebhook(req, res, next) {
  const sig = req.get("X-Signature") || "";
  const expected = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET).update(req.rawBody).digest("hex");
~>  crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  next();
}

module.exports = verifyWebhook;
