require 'yaml'

describe 'yaml' do
  it 'parses' do
    data = YAML.load("a: 1")
    expect(data["a"]).to eq(1)
  end
end
