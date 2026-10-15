import adapter from '@sveltejs/adapter-node';

const config = {
  kit: {
    adapter: adapter(),
    csrf: {
~>      checkOrigin: false,
    },
  },
};

export default config;
