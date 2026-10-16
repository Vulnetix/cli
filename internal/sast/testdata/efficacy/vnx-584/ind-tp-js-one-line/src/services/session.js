'use strict';

const db = require('./db');

async function loadSession(id) {
  let session;
  try {
    session = await db.sessions.findById(id);
    if (!session) {
      throw new Error('session not found');
    }
  } catch (err) {
    logger.warn({ err }, 'session lookup failed');
    throw err;
~>  } finally { return session; }
}

module.exports = { loadSession };
