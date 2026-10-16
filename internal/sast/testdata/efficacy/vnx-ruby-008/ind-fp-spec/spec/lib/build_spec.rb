require 'open3'

describe 'open3' do
  it 'runs' do
    out, _ = Open3.capture2("echo hi")
    expect(out).to eq("hi\n")
  end
end
