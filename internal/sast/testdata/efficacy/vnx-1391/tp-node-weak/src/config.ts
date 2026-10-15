export const config = {
  db: {
    user: "app",
~>    password: "p@ssw0rd",
  },
~>  adminPassword: '12345678',
~>  cachePass: process.env.CACHE_PASSWORD || "1q2w3e4r",
};
