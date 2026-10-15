const handler = onSubmit.bind(this, "checkout");
$("#form").bind("submit", "checkout-form");
client.bind(process.env.LDAP_DN, process.env.LDAP_PASSWORD, done);
