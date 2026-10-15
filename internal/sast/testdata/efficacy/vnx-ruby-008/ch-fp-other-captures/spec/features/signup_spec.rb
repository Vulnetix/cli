require "rails_helper"

RSpec.describe "signup" do
  it "captures output" do
    expect { puts params_for(:user) }.to output.to_stdout
    result = capture2(params: { name: "x" })
    page.pipeline_r(params)
  end
end
