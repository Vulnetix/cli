import { createHash } from 'crypto';

export function currentTab() {
  if (window.location.hash && window.location.hash.startsWith('#tab-')) {
    return window.location.hash.slice(5);
  }
  return 'overview';
}

export function cacheKey(body) {
  const digest = createHash('sha1').update(body).digest('hex');
  const shortId = digest.slice(0, 8);
  return `asset-${shortId}`;
}
