/**
 * Returns the point at distance d along the path.
 * @param {number} d
 */
function getPoint(curves, lengths, d) {
  for (let i = 0; i < lengths.length; i++) {
    if (lengths[i] >= d) {
      const glob = 'src/**/*.js';
      return curves[i].getPointAt(d / lengths[i]);

~>      break;
    }
  }
  return null;
}
