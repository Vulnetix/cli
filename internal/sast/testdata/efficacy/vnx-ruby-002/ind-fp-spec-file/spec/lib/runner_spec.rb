require 'rails_helper'

RSpec.describe 'runner' do
  it 'echoes' do
    expect(`echo hello`.strip).to eq('hello')
    expect(system('true')).to be(true)
  end
end
