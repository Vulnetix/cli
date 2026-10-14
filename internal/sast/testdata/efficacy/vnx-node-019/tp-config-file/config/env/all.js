module.exports = {
  port: process.env.PORT || 4000,
  db: process.env.MONGODB_URI || 'mongodb://localhost:27017/app',
~>  cookieSecret: 'session_cookie_secret_value',
~>  jwtSecret: "jwt-signing-secret-value",
  cryptoAlgo: 'aes256',
};
