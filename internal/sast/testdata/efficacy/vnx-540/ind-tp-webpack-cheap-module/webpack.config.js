const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  mode: 'production',
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].[contenthash].js',
  },
~>  devtool: 'cheap-module-source-map',
  plugins: [new HtmlWebpackPlugin({ template: './public/index.html' })],
};
