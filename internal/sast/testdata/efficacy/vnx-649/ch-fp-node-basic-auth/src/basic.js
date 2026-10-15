function basicAuth(req, res, next) {
  const encoded = (req.headers.authorization || "").split(" ")[1] || "";
  const [user, pass] = Buffer.from(encoded, "base64").toString().split(":");
  if (!checkUser(user, pass)) return res.sendStatus(401);
  next();
}

module.exports = { basicAuth };
