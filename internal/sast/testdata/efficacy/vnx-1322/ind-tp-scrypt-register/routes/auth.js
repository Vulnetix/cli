const crypto = require('crypto');
module.exports = function (router) {
  router.post('/register', async (req, res, next) => {
    const salt = crypto.randomBytes(16);
~>    const hash = crypto.scryptSync(req.body.password, salt, 64);
    await db.users.insert({ email: req.body.email, hash, salt });
    res.sendStatus(201);
  });
};
