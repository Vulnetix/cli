require "rails_helper"

RSpec.describe SessionsController do
  it "does not leak the password" do
    cookies[:password] = "s3cret"
    post :create, params: { email: "a@b.c", password: "s3cret" }
    expect(response).to have_http_status(:found)
  end
end
