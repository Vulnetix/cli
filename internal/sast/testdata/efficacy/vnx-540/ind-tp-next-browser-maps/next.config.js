/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
~>  productionBrowserSourceMaps: true,
  images: { domains: ['cdn.example.com'] },
};

module.exports = nextConfig;
