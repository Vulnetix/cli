require 'spec_helper'

describe 'marshal' do
  it 'roundtrips' do
    blob = Marshal.dump({ a: 1 })
    expect(Marshal.load(blob)).to eq({ a: 1 })
  end
end
