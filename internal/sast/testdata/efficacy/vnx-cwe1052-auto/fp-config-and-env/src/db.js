const mysql = require('mysql2');
const { MongoClient } = require('mongodb');
const config = require('./config');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'db-primary.acme.net',
  user: config.db.user,
  database: config.db.name,
});

const mongo = new MongoClient(process.env.MONGO_URL || 'mongodb://mongo.acme.net:27017');
const cache = createClient({ url: config.redisUrl });

module.exports = { pool, mongo, cache };
