const client = new shopify.clients.Rest({
  session: { shop: 'acme.myshopify.com',
~>    accessToken: "@@sample:shpca_[a-f0-9]{32}@@" },
});
