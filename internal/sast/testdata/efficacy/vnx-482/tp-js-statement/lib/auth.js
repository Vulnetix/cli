function logout(session) {
  session.user = null;
~>  session.isAdmin === false;
}

function reset(state) {
  if (state.attempts > 5) {
~>    state.locked == true
  }
  return state;
}

module.exports = { logout, reset };

function insert(point, isInsert) {
  if (isInsert) {
    if (point.bias == 1) {
      return 1;
    }
    else {
~>      point.bias == -1;
    }
  }
}
