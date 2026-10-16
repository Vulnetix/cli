const isProduction = process.env.NODE_ENV === 'production';

module.exports = {
  mode: isProduction ? 'production' : 'development',
  entry: './src/main.ts',
~>  devtool: isProduction ? 'source-map' : 'eval-cheap-module-source-map',
  resolve: { extensions: ['.ts', '.js'] },
};
