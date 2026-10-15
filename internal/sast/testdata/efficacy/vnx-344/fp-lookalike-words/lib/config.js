const SECRET_NAME = "app-secret";
const API_KEY = process.env.API_KEY;
const order = { state: "pending", nonce: 0 };
const nonceLength = 16;
function setState(s) { return { state: s }; }
