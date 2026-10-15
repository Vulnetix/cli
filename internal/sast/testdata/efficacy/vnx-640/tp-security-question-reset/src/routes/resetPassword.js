const { SecurityAnswerModel } = require('../models/securityAnswer');

async function resetPassword(req, res) {
  const answer = req.body.answer;
  const data = await SecurityAnswerModel.findOne({ where: { email: req.body.email } });
~>  if (data && hmac(answer) === data.answer) {
    await data.user.update({ password: req.body.new });
    return res.json({ ok: true });
  }
  res.status(401).end();
}
module.exports = { resetPassword };
