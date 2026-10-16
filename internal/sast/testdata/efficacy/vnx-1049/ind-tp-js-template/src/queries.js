const { pool } = require('./db');

async function dashboard(teamId) {
  const { rows } = await pool.query(
~>    `SELECT t.id, t.name, count(i.id)
     FROM teams t
     JOIN members m ON m.team_id = t.id
     JOIN issues i ON i.assignee_id = m.user_id
     LEFT JOIN labels l ON l.issue_id = i.id
     LEFT JOIN milestones ms ON ms.id = i.milestone_id
     WHERE t.id = $1
       AND i.created_at > (SELECT max(created_at) - interval '30 days' FROM issues)
     GROUP BY t.id, t.name`,
    [teamId]
  );
  return rows;
}

module.exports = { dashboard };
