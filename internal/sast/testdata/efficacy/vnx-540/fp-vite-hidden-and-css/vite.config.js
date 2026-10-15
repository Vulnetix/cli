export default {
  css: { devSourcemap: true },
  build: {
    sourcemap: 'hidden',
  },
  server: { sourcemap: process.env.NODE_ENV !== 'production' },
};
