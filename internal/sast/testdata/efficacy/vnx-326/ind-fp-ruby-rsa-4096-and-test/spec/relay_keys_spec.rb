require 'openssl'

RSpec.describe RelayKeys do
  it 'parses a small throwaway key quickly' do
    key = OpenSSL::PKey::RSA.new(1024)
    expect(key.private?).to be true
  end
end
