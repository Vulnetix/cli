require 'nokogiri'

class FeedBuilder
  def build(params)
~>    xml = "<feed><title>#{params[:title]}</title></feed>"
    Nokogiri::XML(xml)
  end
end
