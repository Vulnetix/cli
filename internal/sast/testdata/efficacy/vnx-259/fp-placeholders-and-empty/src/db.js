const sequelize = new Sequelize("shop", "shop_user", process.env.DB_PASSWORD, { dialect: "postgres" });
const anon = new Sequelize("sqlite::memory:");
const local = new Sequelize("shop", "root", "", { dialect: "mysql" });
const t = nodemailer.createTransport({ auth: { user: process.env.U, pass: process.env.P } });
const tpl = new Sequelize("shop", "app", "${DB_PASS}");
const tpl2 = new Sequelize("database", "username", "password", { dialect: "sqlite" });
