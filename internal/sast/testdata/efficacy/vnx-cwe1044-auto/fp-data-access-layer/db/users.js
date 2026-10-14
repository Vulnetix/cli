const pool = require('./pool')

exports.findUser = (id) => pool.query('SELECT id, name FROM users WHERE id = $1', [id])
