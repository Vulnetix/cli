const crypto = require('crypto');
const { v4: uuidv4, v1: uuidv1 } = require('uuid');

const resetToken = uuidv4();
const sessionId = crypto.randomUUID();
const traceId = uuidv1();
