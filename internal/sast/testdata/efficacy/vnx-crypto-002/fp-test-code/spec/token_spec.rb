require "digest"

RSpec.describe "tokens" do
  it "matches the legacy digest" do
    expect(token).to eq(Digest::SHA1.hexdigest("fixture"))
  end
end
