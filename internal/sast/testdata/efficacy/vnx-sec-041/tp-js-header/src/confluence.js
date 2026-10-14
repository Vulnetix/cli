const auth = Buffer.from(
~>  `svc@acme.io:@@sample:ATATT3xFfGF0[A-Za-z0-9_-]{172}=[A-F0-9]{8}@@`
).toString('base64');
module.exports = { headers: { Authorization: `Basic ${auth}` } };
