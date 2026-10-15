require "nokogiri"

class ItemService
  def initialize(params)
    @params = params
  end

  def build(params)
    name = params[:name]
~>    xml = "<item><name>#{name}</name><price>#{params[:price]}</price></item>"
    Nokogiri::XML(xml)
  end
end
