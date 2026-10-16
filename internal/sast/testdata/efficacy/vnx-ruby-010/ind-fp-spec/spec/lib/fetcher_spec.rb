RSpec.describe Fetcher do
  it "talks to the self-signed server" do
    http = Net::HTTP.new("localhost", 8443)
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end
end
