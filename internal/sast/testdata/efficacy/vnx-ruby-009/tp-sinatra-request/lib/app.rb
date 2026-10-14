require "sinatra/base"

class Api < Sinatra::Base
  get "/settings/:name" do
~>    settings.send(params["name"]).to_s
  end

  post "/call" do
    method_name = request.params["method"]
~>    Calculator.new.public_send(method_name, *JSON.parse(request.body.read))
  end
end
