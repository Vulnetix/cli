const db = require('./db');

function auditTrail(userId, cb) {
  db.query(
~>    'SELECT e.id, e.kind, u.name, r.title, g.name, p.label ' +
    'FROM events e ' +
    'INNER JOIN users u ON u.id = e.user_id ' +
    'LEFT JOIN roles r ON r.id = u.role_id ' +
    'LEFT JOIN groups g ON g.id = u.group_id ' +
    'LEFT JOIN permissions p ON p.role_id = r.id ' +
    'LEFT JOIN projects pr ON pr.id = e.project_id ' +
    'WHERE e.user_id = ?',
    [userId],
    cb
  );
}

module.exports = { auditTrail };
