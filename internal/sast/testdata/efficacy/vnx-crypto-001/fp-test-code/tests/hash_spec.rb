require "digest"

RSpec.describe User do
  it "stores the legacy digest" do
    expect(user.password).to eq(Digest::MD5.hexdigest("secret"))
  end
end
