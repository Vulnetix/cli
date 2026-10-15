// lusca({ csrf: false }) would switch protection off; keep it on.
const lusca = require('lusca');
const message = "Set csrf: false only in tests";
module.exports = (app) => app.use(lusca({ csrf: true }));
