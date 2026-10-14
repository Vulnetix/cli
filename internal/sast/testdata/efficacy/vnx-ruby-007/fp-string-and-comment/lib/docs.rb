module Docs
  # YAML.load(params[:x]) is dangerous on Psych 3
  WARNING = "Do not call YAML.load(request.body.read) on client data"

  def self.parse(text)
    YAML.safe_load(text)
  end
end
