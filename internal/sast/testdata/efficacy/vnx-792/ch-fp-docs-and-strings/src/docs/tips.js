// do not write s.replace('<', '&lt;'): it only escapes the first one
const TIP = "s.replace('<', '&lt;') escapes only the first bracket";
/*
 * s.replace(/</, '&lt;') has the same problem
 */
const placeholder = template.replace('{{body}}', '<p>' + body + '</p>');
module.exports = { TIP, placeholder };
