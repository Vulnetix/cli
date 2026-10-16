// Never do: connection.query("SELECT * FROM users WHERE id = " + req.params.id)
const example = "pool.query(`SELECT * FROM t WHERE a = '${a}'`)";
console.log("running " + example);
