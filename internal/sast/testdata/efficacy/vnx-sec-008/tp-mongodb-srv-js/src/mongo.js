const { MongoClient } = require("mongodb");

~>const uri = `mongodb+srv://svc:@@sample:[A-Za-z0-9]{16}@@@cluster0.ab1cd.mongodb.net/app?retryWrites=true`;
module.exports = new MongoClient(uri);
