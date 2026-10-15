const express = require("express");
const security = require("../security");
const app = express();
security(app);
app.listen(8080);
