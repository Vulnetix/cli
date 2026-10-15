const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// the key prefix looks like SG.<id>.<secret>
const truncated = '@@sample:S[G][.]A[b]3d[E]f7[h]Ij[.]Kl[9]nO[p]@@';
const display = `SG.${keyId}.${'*'.repeat(8)}`;
module.exports = { sgMail, truncated, display };
