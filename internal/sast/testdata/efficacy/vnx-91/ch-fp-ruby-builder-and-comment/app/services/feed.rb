require "builder"

class Feed
  def render(params)
    xml = Builder::XmlMarkup.new
    # do not build "<title>#{params[:title]}</title>" by hand
    xml.instruct!
    xml.feed do
      xml.title params[:title]
    end
    xml.target!
  end
end
