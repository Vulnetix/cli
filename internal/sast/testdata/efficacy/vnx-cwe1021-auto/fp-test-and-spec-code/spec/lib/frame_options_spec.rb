describe Rack::Protection::FrameOptions do
  it 'allows a custom value' do
    mock_app do
      use Rack::Protection::FrameOptions, frame_options: 'ALLOW-FROM foo'
      run DummyApp
    end
    expect(get('/').headers['X-Frame-Options']).to eq('ALLOW-FROM foo')
  end

  it 'does not override a header the app set' do
    mock_app with_headers('x-frame-options' => 'allow')
    expect(get('/').headers['X-Frame-Options']).to eq('allow')
  end
end
