require "open3"

class GrepApp
  def call(env)
    req = Rack::Request.new(env)
    pattern = req.params["q"]
~>    Open3.popen3("grep -rn '#{pattern}' /srv/docs") do |stdin, stdout, stderr, thr|
      return [200, {}, [stdout.read]]
    end
  end
end
