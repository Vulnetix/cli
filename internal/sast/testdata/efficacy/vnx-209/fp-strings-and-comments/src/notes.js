// Never do res.send(err.stack) in production: it leaks file paths.
/* res.status(500).json({ stack: err.stack }) */
const help = "do not call res.send(err.stack)";
const stackTrace = require('stack-trace');
res.json({ status: 'ok', stack: stackTrace.parse(new Error()).length });
