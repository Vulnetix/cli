require 'sinatra'

get '/convert' do
~>  IO.popen("convert #{params['src']} out.png").read
end

post '/archive' do
  name = params[:name]
~>  exec("tar czf /tmp/#{name}.tgz /srv/data")
end

get '/read' do
~>  open(params[:source]).read
end

post '/shell' do
  cmd = request.params["cmd"]
~>  system("sh", "-c", cmd)
end
