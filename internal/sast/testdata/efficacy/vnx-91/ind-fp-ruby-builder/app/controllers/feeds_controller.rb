require "nokogiri"
require "cgi"

class FeedsController < ApplicationController
  def create
    builder = Nokogiri::XML::Builder.new do |x|
      x.feed { x.title params[:title] }
    end
    summary = "<summary>#{CGI.escapeHTML(params[:summary].to_s)}</summary>"
    Feed.create!(body: builder.to_xml + summary)
    head :created
  end
end
