class TemplatesController < ApplicationController
  def preview
    source = params[:template]
    doc = source.to_s.strip
~>    @template = YAML.unsafe_load(doc)
    blob = Base64.decode64(cookies[:layout])
~>    @layout = Psych.load(
      blob
    )
  end
end
