require "sinatra"

get "/thumb" do
  name = params["file"]
  cmd = "convert uploads/" + name + " -resize 64x64 thumbs/out.png"
~>  system(cmd)
  "done"
end
