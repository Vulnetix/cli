const { Sequelize } = require("sequelize");

~>const sequelize = new Sequelize("shop", "shop_user", "pr0d-Passw0rd", {
  host: "db.internal",
  dialect: "postgres",
});

const transporter = nodemailer.createTransport({
  host: "smtp.example.org",
  auth: {
    user: "mailer@example.org",
~>    pass: "n0dem4iler-pass",
  },
});

~>app.use(basicAuth({ users: { admin: "supers3cret-admin" } }));
