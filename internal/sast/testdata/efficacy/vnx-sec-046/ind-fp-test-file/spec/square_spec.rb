it "builds" do
  token = "EAAA@@sample:[A-Za-z0-9_-]{60}@@"
  expect(build(token)).to be_ok
end
