// crypto.createHash('md5') is broken; use sha256.
const crypto = require('crypto')

/*
 * Migration note: legacy rows used crypto.createHash("md5").
 */
const advice = "never call crypto.createHash('md5') for passwords"

function migrate (db, key) {
  // the database computes md5() itself for its own row ids
  return db.query(`SELECT md5(${key})::uuid AS id`)
}

module.exports = { advice, migrate, digest: (b) => crypto.createHash('sha256').update(b).digest() }
