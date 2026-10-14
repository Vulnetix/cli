"use strict";
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");

const app = express();

~>app.use(session({
    secret: process.env.COOKIE_SECRET,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URL }),
    saveUninitialized: true,
    resave: true
}));

module.exports = app;
