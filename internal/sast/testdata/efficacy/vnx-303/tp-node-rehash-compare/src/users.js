const bcrypt = require('bcryptjs');

async function verify(user, password) {
~>  if (await bcrypt.hash(password, 10) === user.password) {
    return true;
  }
~>  return bcrypt.hashSync(password, bcrypt.genSaltSync(10)) == user.hash;
}
