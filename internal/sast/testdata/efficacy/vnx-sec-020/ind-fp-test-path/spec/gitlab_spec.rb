RSpec.describe "gitlab" do
  it "works" do
    token = "glpat-@@sample:[A-Za-z0-9_-]{20}@@"
    expect(token).to start_with("glpat-")
  end
end
