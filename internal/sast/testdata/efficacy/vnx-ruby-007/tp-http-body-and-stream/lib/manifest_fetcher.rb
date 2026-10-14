require "net/http"
require "yaml"

class ManifestFetcher
  def fetch(uri)
    res = Net::HTTP.get_response(uri)
~>    YAML.load(res.body)
  end

  def each_doc(message)
~>    YAML.load_stream(message.body) { |doc| yield doc }
  end
end
