const user = process.env.MONGO_USER;
const pass = process.env.MONGO_PASS;
export const uri = `mongodb+srv://${user}:${pass}@cluster0.ab1cd.mongodb.net/app`;
export const viaConcat = "mongodb://" + user + ":" + pass + "@mongo.acme.internal/app";
export const nopass = "mongodb://mongo.acme.internal:27017/app";
export const defaults = "mongodb://mongo:mongo@mongo.acme.internal/app";
