require 'nokogiri'

def parse(xml)
  Nokogiri::XML(xml) do |config|
~>    config.dtdload
  end
end

def parse2(xml)
~>  Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::DTDLOAD)
end
