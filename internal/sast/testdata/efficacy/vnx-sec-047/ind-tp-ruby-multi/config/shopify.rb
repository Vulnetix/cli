ShopifyAPI::Context.setup(
  api_key: ENV["SHOPIFY_KEY"],
~>  api_secret_key: "shpss_@@sample:[a-f0-9]{32}@@",
  scope: "read_products",
)
password = "x"
~>legacy = "shppa_@@sample:[a-f0-9]{32}@@"
