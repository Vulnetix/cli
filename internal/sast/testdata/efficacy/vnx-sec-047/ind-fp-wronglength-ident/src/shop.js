const a = "shpat_@@sample:[a-f0-9]{31}@@";
const b = "shpat_@@sample:[a-f0-9]{33}@@";
const c = "myshpat_@@sample:[a-f0-9]{32}@@";
const d = "shpat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const e = "shpat_00000000000000000000000000000000";
const f = process.env.SHOPIFY_ACCESS_TOKEN;
module.exports = { a, b, c, d, e, f };
