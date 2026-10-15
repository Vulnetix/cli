// Never write if (req.cookies.isAdmin === "true") — the client sets that cookie.
const warning = "if ($_COOKIE['admin'] == 1) trusts the browser";
/* request.COOKIES.get("admin") == "1" is forgeable */
module.exports = warning;
