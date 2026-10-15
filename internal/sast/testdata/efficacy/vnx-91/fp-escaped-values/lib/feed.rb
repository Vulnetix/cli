require 'nokogiri'
require 'cgi'

def feed(params)
  Nokogiri::XML("<feed><title>#{CGI.escapeHTML(params[:title])}</title></feed>")
end
