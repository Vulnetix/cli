// Example of the bug: obj[req.body.a][req.body.b] = req.body.c;
const help = 'never write target[key] = merge(target[key], source[key]) without a key check';
const snippet = `settings[req.query.section][req.query.key] = value`;
module.exports = { help, snippet };
