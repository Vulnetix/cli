async function sendLoginCode(req, res) {
  const user = await findUser(req.body.phone);
~>  const n = Math.floor(100000 + Math.random() * 900000);
  const message = `Your login code is ${n}`;
  await sms.send(user.phone, message);
  req.session.otp = n;
  res.json({ sent: true });
}

module.exports = { sendLoginCode };
