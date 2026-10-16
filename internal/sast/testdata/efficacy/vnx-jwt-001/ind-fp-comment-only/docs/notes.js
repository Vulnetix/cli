// Never do this: jwt.decode(token, key, { verify_signature: False })
// Also avoid JWT.decode(token, nil, false) in ruby.
const msg = "options={'verify_signature': False} disables checking";
module.exports = { msg };
