module.exports = {
  mode: 'production',
  devtool: 'hidden-source-map',
};
module.exports.alt = { mode: 'production', devtool: 'nosources-source-map' };
module.exports.off = { mode: 'production', devtool: false };
