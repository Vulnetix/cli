class SearchController < ApplicationController
  TEMPLATE = File.read(Rails.root.join('app/views/search/row.html.erb'))

  def index
    @q = params[:q]
    render :index, locals: { q: params[:q] }
  end

  def row
    html = ERB.new(TEMPLATE).result_with_hash(name: params[:name])
    render html: html
  end

  def banner
    render inline: "<p><%= h params[:msg] %></p>"
  end
end
