// Example: GET /login?password=secret is how NOT to call the API
const EXAMPLE = "https://api.example.com/items?api_key=YOUR_API_KEY";
const RESET_DOC = "see /reset?token=<token> in the e-mail";

function build(page) {
  return `/items?page=${page}&limit=20`;
}

module.exports = { EXAMPLE, RESET_DOC, build };
