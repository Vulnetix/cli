require 'nokogiri'

def parse_safe(xml)
  Nokogiri::XML(xml) { |config| config.strict.nonet }
end

def parse_explicit(xml)
  Nokogiri::XML(xml) { |config| config.nodtdload.nonet }
end
