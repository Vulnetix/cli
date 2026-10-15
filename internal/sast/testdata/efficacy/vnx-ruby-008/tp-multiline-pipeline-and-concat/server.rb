require "sinatra"
require "open3"

get "/thumb" do
  name = request.params["name"]
~>  Open3.pipeline_rw(
    "convert #{name} -resize 64x64 png:-",
    "base64"
  ) do |i, o, _ts|
    o.read
  end
end

post "/grep" do
~>  out, _ = Open3.capture2 "grep -r '" + params["q"] + "' /srv/docs"
  out
end
