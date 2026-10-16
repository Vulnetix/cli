RSpec.describe Notifier do
  it "posts" do
    url = "https://hooks.slack.com/services/T@@sample:[A-Z0-9]{9}@@/B@@sample:[A-Z0-9]{10}@@/@@sample:[A-Za-z0-9]{24}@@"
    expect(described_class.new(url)).to be_valid
  end
end
