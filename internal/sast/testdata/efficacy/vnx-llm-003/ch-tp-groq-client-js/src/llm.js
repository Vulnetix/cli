const Groq = require("groq-sdk");

const groq = new Groq({
~>  apiKey: "@@sample:gsk_[A-Za-z0-9]{52}@@",
});

module.exports = groq;
