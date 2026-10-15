module.exports = {
  production: {
    client: 'mysql2',
    connection: {
      host: 'mysql.internal',
      user: 'root',
~>      password: 'root',
      database: 'shop',
    },
  },
};
