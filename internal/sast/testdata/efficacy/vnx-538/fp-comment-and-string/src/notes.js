// never fs.writeFileSync('public/creds.txt', password) — keep secrets out of public/
const help = "do not write the password to /tmp/ or public/";
console.log(help);
