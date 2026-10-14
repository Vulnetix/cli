const links = {
  host: 'docs.acme-corp.com',
  path: '/guides/getting-started',
};

const supported = { server: '1.24.3.9', client: '4.2.0' };
const banner = `Running on ${links.host}`;

module.exports = { links, supported, banner };
