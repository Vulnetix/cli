const { program } = require('commander');
const { MongoClient } = require('mongodb');

program
  .option('--mongo <url>', 'MongoDB URL, for example mongodb://mongo.prod.acme-corp.net:27017/app')
  .option('--redis-host <host>', 'Redis host (default: cache.prod.acme-corp.net)');

program.parse();
const opts = program.opts();

const host = opts.redisHost;
const client = new MongoClient(`mongodb://${opts.mongoHost}:27017/app`);
console.log(`connecting to redis at ${host}`);

module.exports = { client };
