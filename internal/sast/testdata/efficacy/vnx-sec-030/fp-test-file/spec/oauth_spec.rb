RSpec.describe OAuthConfig do
  it "loads the secret" do
    expect(described_class.new("GOCSPX-@@sample:[A-Za-z0-9]{28}@@").valid?).to be true
  end
end
