require 'nokogiri'

class FeedParser
  def parse(xml)
~>    Nokogiri::XML(xml) { |config| config.strict.dtdload }
  end

  def parse_with_options(xml)
~>    options = Nokogiri::XML::ParseOptions::DTDLOAD | Nokogiri::XML::ParseOptions::NOENT
    Nokogiri::XML(xml, nil, nil, options)
  end
end
