// mongodb://admin:admin@localhost was the old dev default
const hint = "do not use auth=('admin', 'admin') in production";
if (user === "admin" && password === "admin") { warn(); }
const roles = Rule.contains("admin", "editor");
module.exports = { hint, roles };
