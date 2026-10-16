require 'net/http'
require 'yaml'

class YamlImporter
  def from_upload
    upload = params[:file]
~>    data = YAML.load_file(upload.tempfile)
    data
  end

  def from_remote(uri)
    res = Net::HTTP.get_response(uri)
~>    YAML.load(res.body)
  end

  def from_cookie
~>    YAML::load(Base64.decode64(cookies[:state]))
  end

  def stream
~>    YAML.load_stream(request.raw_post)
  end
end
