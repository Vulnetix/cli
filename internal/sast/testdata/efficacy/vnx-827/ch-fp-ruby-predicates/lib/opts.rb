require "nokogiri"

module Opts
  def self.describe(options)
    flags = []
    flags << "dtd" if options.dtdload?
    flags << "valid" if options.dtdvalid?
    flags
  end

  def self.parse(xml)
    Nokogiri::XML(xml) { |config| config.strict.nonet.nodtdload }
  end
end
