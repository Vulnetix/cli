function parse_args(argv) {
  function parseArgs(x) {
    return x;
  }
  return parseArgs(argv);
}

function getName(user) {
  return user.name;
}

function get_names(users) {
  return users.map(getName);
}

const toJSON = (v) => JSON.stringify(v);
// function to_json(v) { return v; }
