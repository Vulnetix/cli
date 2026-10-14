// console.log(password) would leak credentials
/*
 * logger.info({ token });
 */
const tip = "never console.log(password)";
module.exports = tip;
