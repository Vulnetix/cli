namespace :keys do
  desc 'Generate a signing key for the webhook relay'
  task generate: :environment do
~>    key = OpenSSL::PKey::RSA.new(1024)
    File.write(Rails.root.join('config', 'relay.pem'), key.to_pem)
  end
end
