const smtp = nodemailer.createTransport({ host, port: 587, secure: false });
const ws = new WebSocket(url, { secure: false });
const db = new Pool({ ssl: { rejectUnauthorized: true }, secure: false });
const message = "Set httpOnly: false only for the CSRF cookie";
