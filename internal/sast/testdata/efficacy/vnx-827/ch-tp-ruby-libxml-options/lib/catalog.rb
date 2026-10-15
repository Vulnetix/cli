require "libxml"

module Catalog
  def self.parse(xml)
~>    LibXML::XML.default_load_external_dtd = true
~>    parser = LibXML::XML::Parser.string(xml, options: LibXML::XML::Parser::Options::DTDLOAD)
    parser.parse
  end
end
