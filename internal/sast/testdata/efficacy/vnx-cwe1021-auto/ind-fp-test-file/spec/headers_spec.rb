require 'rack/test'

RSpec.describe 'framing' do
  it 'is permissive in the fixture app' do
    header 'X-Frame-Options', 'ALLOWALL'
    get '/widget'
    expect(last_response.headers['X-Frame-Options']).to eq('ALLOWALL')
  end
end
