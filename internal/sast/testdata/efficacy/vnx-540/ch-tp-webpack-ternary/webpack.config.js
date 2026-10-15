const path = require('path');

const isProduction = process.env.NODE_ENV === 'production';

module.exports = {
  mode: isProduction ? 'production' : 'development',
  entry: './src/index.js',
  output: { path: path.resolve(__dirname, 'dist'), filename: '[name].[contenthash].js' },
~>  devtool: isProduction ? 'source-map' : 'eval-cheap-module-source-map',
};
