require "nokogiri"

class FeedsController < ApplicationController
  def create
~>    xml = "<feed><title>#{params[:title]}</title></feed>"
    doc = Nokogiri::XML(xml)
    Feed.create!(body: doc.to_xml)
    head :created
  end
end
