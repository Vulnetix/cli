~>const xssPatterns = ['<script', 'javascript:', 'onerror', 'onload'];

function isSafeComment(body) {
  const lower = body.toLowerCase();
  return !xssPatterns.some((p) => lower.includes(p));
}

module.exports = { isSafeComment };
