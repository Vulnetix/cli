// A client-side helper that mimics the Jinja filter for previews.
const preview = (s) => `{{ ${s}|safe }}`.length;
const isSafe = value | safe;
export { preview, isSafe };
