require "rails_helper"

RSpec.describe "Reports" do
  it "accepts basic auth" do
    get "/reports", headers: { "Authorization" => "Basic @@sample:Z[G]Vw[b]G9[5]On[M]0Z[k]x5[L]VB[3]N3[h]R@@" }
    expect(response).to have_http_status(:ok)
  end
end
