require 'nokogiri'

doc = Nokogiri::XML(xml) { |config| config.nodtdload.nonet }
puts "dtd on" if doc.options.dtdload?
# config.dtdload
