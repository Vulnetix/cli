const url = `mysql://${process.env.DB_USER}:${process.env.DB_PASS}@db:3306/app`;
const viaConcat = "mysql://app:" + process.env.DB_PASS + "@db.prod.acme.io/app";
const defaults = "mysql://root:root@db.prod.acme.io/app";
const nopass = "mysql://app@db.prod.acme.io/app";
module.exports = { url, viaConcat, defaults, nopass };
