namespace :sync do
  task pull: :environment do
    client = HTTPClient.new
~>    client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
    client.get(ENV["SYNC_URL"])
  end
end
