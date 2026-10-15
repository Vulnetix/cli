const bcrypt = require('bcrypt');
const { User } = require('./db');

async function registerUser(email, password) {
  const hash = await bcrypt.hash(password, 12);
  return User.create({
    email,
    password: hash,
~>    role: 'admin',
  });
}

const signUp = async (req, res) => {
  const user = new User({ email: req.body.email });
~>  user.isAdmin = true;
  await user.save();
  res.json({ id: user.id });
};

module.exports = { registerUser, signUp };
