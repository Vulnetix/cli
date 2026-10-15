// Never write: if (req.headers['x-role'] === 'admin') { ... }
/* if (user.role = 'admin') used to be here */
const HELP = "if (req.cookies.isAdmin) grants admin from a cookie";
const RULE = 'user.role.includes("admin") is a substring test';
