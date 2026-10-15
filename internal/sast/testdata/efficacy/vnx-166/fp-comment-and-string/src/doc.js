// const token = req.headers.authorization.split(' ')[1]  breaks when the header has no space
/* request.headers.get("Authorization").split(" ")[1] */
const hint = "req.headers.authorization.split(' ')[1]"
module.exports = { hint }
