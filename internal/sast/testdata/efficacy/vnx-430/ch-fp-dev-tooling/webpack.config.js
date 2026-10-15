const path = require('path');

module.exports = {
  entry: './src/index.js',
  output: { path: path.resolve(__dirname, 'dist') },
  devServer: {
    static: __dirname,
    port: 9000,
  },
};
