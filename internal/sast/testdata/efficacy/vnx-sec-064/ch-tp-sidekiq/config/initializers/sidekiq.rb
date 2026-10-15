Sidekiq.configure_server do |config|
~>  config.redis = { url: "rediss://:@@sample:[A-Za-z0-9]{20}@@@cache-prod.acme.internal:6380/1" }
end
