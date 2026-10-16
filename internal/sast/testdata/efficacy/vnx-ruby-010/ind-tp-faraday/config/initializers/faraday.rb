~>conn = Faraday.new(url: ENV["API_BASE"], ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE }) do |f|
  f.adapter Faraday.default_adapter
end
