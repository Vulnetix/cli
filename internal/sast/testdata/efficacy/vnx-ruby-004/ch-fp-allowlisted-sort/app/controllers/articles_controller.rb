class ArticlesController < ApplicationController
  SORTABLE = %w[title published_at].freeze

  def index
    sort = SORTABLE.include?(params[:sort]) ? params[:sort] : "published_at"
    dir = params[:dir] == "asc" ? "asc" : "desc"
    @articles = Article.order("#{sort} #{dir}")
    @page = Article.order(params[:sort] == "title" ? :title : :published_at)
  end
end
