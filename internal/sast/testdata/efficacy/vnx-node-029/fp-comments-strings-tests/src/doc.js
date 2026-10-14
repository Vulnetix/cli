// res.cookie('token', token) without httpOnly is unsafe
/*
 * res.cookie('session', id);
 */
const help = "call res.cookie('token', value) with httpOnly: true";
module.exports = help;
