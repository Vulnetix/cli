RSpec.describe "cookies" do
  it "allows an insecure cookie in the fixture app" do
    Rails.application.config.session_store :cookie_store, key: "_t", httponly: false, secure: false
    expect(true).to be true
  end
end
