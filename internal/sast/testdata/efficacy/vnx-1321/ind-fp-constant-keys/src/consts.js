function init(config, items) {
  config.server.port = 8080;
  config['db'].host = 'localhost';
  for (let i = 0; i < items.length; i++) {
    grid[i][0] = items[i];
  }
}
// store[req.body.section][req.body.key] = 1;
const doc = "obj[req.body.a][req.body.b] = v";
module.exports = init;
