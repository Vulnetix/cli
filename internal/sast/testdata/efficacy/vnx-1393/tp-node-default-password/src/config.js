module.exports = {
  db: {
    host: process.env.DB_HOST,
    user: "app",
~>    password: "postgres",
  },
~>  adminPassword: 'admin',
~>  rabbitPass: process.env.RABBIT_PASSWORD || "guest",
~>  mqPassword: process.env.MQ_PASSWORD ?? 'changeme',
};
