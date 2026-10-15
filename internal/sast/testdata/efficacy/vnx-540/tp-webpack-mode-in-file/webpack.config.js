module.exports = {
  mode: "production",
  entry: "./src/index.js",
~>  devtool: "inline-source-map",
  output: { filename: "[name].[contenthash].js" },
};
