const { Sequelize } = require("sequelize");
const nodemailer = require("nodemailer");
const ldap = require("ldapjs");

~>const sequelize = new Sequelize("shop", "shop_app", "Seq-Sh0p-99", {
  host: "db.internal",
  dialect: "postgres",
});

const transporter = nodemailer.createTransport({
  host: "smtp.example.org",
  port: 587,
  auth: {
    user: "mailer@example.org",
~>    pass: "Nm-Mailer-77",
  },
});

function directory() {
  const client = ldap.createClient({ url: "ldap://ldap.internal" });
~>  client.bind("cn=admin,dc=example,dc=org", "Ld4p-Admin!", (err) => {
    if (err) throw err;
  });
  return client;
}

module.exports = { sequelize, transporter, directory };
