// Unsafe: User.findOne({ username: req.body.username })
const msg = 'never pass req.query straight to collection.find(req.query)';
module.exports = msg;
