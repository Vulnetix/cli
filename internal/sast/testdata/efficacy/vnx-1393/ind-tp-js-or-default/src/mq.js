module.exports = {
  host: process.env.RABBIT_HOST,
~>  rabbitPass: process.env.RABBIT_PASSWORD || "guest",
};
