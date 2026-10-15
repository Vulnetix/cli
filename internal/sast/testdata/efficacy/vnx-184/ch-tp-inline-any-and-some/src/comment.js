function validateComment(body) {
~>  if (['<script', 'javascript:', 'onerror'].some((t) => body.toLowerCase().includes(t))) {
    throw new Error('markup is not allowed');
  }
  return body;
}

module.exports = { validateComment };
