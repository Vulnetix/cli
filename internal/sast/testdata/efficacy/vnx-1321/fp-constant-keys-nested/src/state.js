const state = { users: {}, groups: {} };

function addUser(user) {
  state['users'][user.id] = user;
  state.groups[user.group] = state.groups[user.group] || [];
}

function grid(rows, cols) {
  const m = [];
  for (let i = 0; i < rows; i++) {
    m[i] = [];
    for (let j = 0; j < cols; j++) {
      m[i][j] = 0;
    }
  }
  return m;
}

module.exports = { addUser, grid };
