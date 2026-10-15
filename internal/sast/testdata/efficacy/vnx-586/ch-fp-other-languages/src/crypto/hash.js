const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const enc = cipher.update(data);
cipher.final();
builder.finalize();
