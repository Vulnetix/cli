class Thumbnailer
  def call(env)
    req = Rack::Request.new(env)
    name = req.params["name"]
~>    pid = Process.spawn("convert uploads/#{name} -resize 64x64 thumbs/#{name}")
    Process.wait(pid)
    [200, { "content-type" => "text/plain" }, ["done"]]
  end
end
