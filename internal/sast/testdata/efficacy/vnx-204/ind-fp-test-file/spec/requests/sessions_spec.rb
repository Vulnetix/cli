require "rails_helper"

RSpec.describe "Sessions", type: :request do
  it "does not reveal that the email is unknown" do
    post "/login", params: { email: "nobody@example.com", password: "x" }
    expect(response.body).not_to include("Email not found")
    expect(response.body).not_to include("Wrong password")
    expect(response.body).to include("Invalid email or password")
  end
end
