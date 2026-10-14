require "sinatra/base"

class StatusApp < Sinatra::Base
~>  set :protection, :except => :frame_options

  get "/status" do
    erb :status
  end
end
