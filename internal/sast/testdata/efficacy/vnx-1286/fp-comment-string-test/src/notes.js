// const id = JSON.parse(req.params.id) would throw on bad input
const doc = "call JSON.parse(req.body) inside a try block";
const n = parseInt(process.env.RETRIES, 10);
/*
const preTax = parseInt(req.body.preTax);
*/
module.exports = { doc, n };
