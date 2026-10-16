const { defineConfig } = require('@vue/cli-service');

module.exports = defineConfig({
  transpileDependencies: true,
  publicPath: '/app/',
~>  productionSourceMap: true,
  devServer: { port: 8081 },
});
