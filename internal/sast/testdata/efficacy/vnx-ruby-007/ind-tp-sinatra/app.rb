require 'sinatra'
require 'yaml'

post '/config' do
  payload = request.body.read
~>  cfg = YAML.load(payload)
  cfg.to_json
end

post '/legacy' do
~>  YAML.unsafe_load(params[:doc])
end
