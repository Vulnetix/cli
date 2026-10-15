const isProd = process.env.NODE_ENV === 'production';

module.exports = {
  mode: isProd ? 'production' : 'development',
  entry: './src/main.js',
  devtool: isProd ? false : 'eval-source-map',
};
