require "net/http"

class DeployHook
  def fetch(uri)
    response = Net::HTTP.get_response(uri)
    spec = response.body
~>    Psych.load(spec)
  end
end
