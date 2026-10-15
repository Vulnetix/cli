function load(req) {
  const name = req.query.name;
  const m = eval("require('fs')");
  return redis.eval(script, 1, name);
}
