import shopify

~>PASSWORD = '@@sample:shppa_[a-f0-9]{32}@@'
~>SHARED_SECRET = '@@sample:shpss_[a-f0-9]{32}@@'
shopify.ShopifyResource.set_site(f"https://key:{PASSWORD}@acme.myshopify.com/admin")
