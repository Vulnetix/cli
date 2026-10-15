const { v1: uuidv1 } = require('uuid');
const uuid = require('uuid');

~>const resetToken = uuidv1();

function login(req, res) {
~>  res.cookie('session', uuid.v1(), { httpOnly: true });
}

module.exports = { resetToken, login };
