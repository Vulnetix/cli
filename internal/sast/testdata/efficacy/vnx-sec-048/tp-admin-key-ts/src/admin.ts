~>const ADMIN_KEY = `@@sample:sk-admin-[a-z]{3}[A-Z]{3}[0-9]{3}[A-Za-z0-9_-]{50}@@`;
await fetch("https://api.openai.com/v1/organization/users", { headers: { Authorization: `Bearer ${ADMIN_KEY}` } });
