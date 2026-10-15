const auth = Buffer.from(`${username}:${password}`).toString("base64");
const header = "Basic " + btoa(user + ":" + password);
const creds = Buffer.from(username + ":" + password).toString("base64");
const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
const enc = CryptoJS.AES.encrypt(plaintext, password).toString();
const field = btoa(passwordFieldId);
