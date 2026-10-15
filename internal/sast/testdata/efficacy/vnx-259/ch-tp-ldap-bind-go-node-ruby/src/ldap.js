const ldap = require("ldapjs");

const client = ldap.createClient({ url: process.env.LDAP_URL });
~>client.bind("cn=admin,dc=example,dc=org", "Adm1nLdap$", (err) => {
  if (err) throw err;
});
