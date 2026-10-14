// Do not call fs.readFile(req.query.file) without validation.
/*
 * res.sendFile(path.join(__dirname, req.params.name)) is a traversal bug.
 */
const warning = "fs.readFileSync('./uploads/' + req.params.name) is unsafe";
module.exports = { warning };
